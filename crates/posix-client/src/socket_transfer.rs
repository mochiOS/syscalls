//! Ancillary transfer over the dedicated socket worker endpoint. FD numbers
//! remain local; only explicitly attached, attenuated authority crosses IPC.
use crate::{ClientError, ObjectHandleAttachment as Handle, ObjectHandles, ObjectTransport};
use mochios_posix_protocol::{InheritedFdMetadata, socket_transfer as wire};

/// The caller owns `receipt` and must close it on every exit, including partial
/// delivery, cancellation and failure. Closing it releases undelivered rights.
#[derive(Debug)]
#[must_use = "close the owned receipt after delivery or abort"]
pub struct Received<'a, H> {
    pub message: wire::ReceiveReply<'a>,
    pub receipt: Option<Handle<H>>,
}

/// Native rights are authoritative; metadata is only a POSIX dispatch hint.
/// Sender CLOEXEC is not inherited. The receiver chooses its local FD flags.
#[derive(Debug)]
#[must_use = "install or close the received Handle"]
pub struct ReceivedFile<H> {
    pub object: Handle<H>,
    pub metadata: InheritedFdMetadata,
}

/// Owns `files[..count]`. Install these into reserved local FD slots or close
/// them on failure. No other batch or receipt is owned by this value.
#[derive(Debug)]
#[must_use = "install or close every received Handle in this batch"]
pub struct Delivery<H> {
    pub files: [Option<ReceivedFile<H>>; crate::MAX_OBJECT_HANDLES],
    pub count: usize,
}

/// Borrowed source reference. Repeating it transfers independent references to
/// the same object; it never transfers a sender-local FD number or CLOEXEC.
#[derive(Clone, Copy, Debug)]
pub struct SendFile<H> {
    pub object: Handle<H>,
    pub metadata: InheritedFdMetadata,
}

fn attach<T: ObjectTransport>(
    handles: &mut ObjectHandles<T::Handle>,
    source: Handle<T::Handle>,
    rights: u64,
) -> Result<(), ClientError<T::Error>>
where
    T::Handle: Default + Eq,
{
    let required = rights | mnu_abi::HANDLE_RIGHT_TRANSFER;
    if source.handle == T::Handle::default() || source.rights & required != required {
        return Err(ClientError::Remote(-13));
    }
    handles
        .push(Handle {
            handle: source.handle,
            rights,
        })
        .map_err(|_| ClientError::RequestTooLarge)
}

fn cleanup<H: Copy + Default + Eq>(
    handles: &ObjectHandles<H>,
    borrowed: &[H],
    mut close: impl FnMut(H),
) {
    for (index, item) in handles.iter().enumerate() {
        // Real kernel replies allocate distinct local slots. Reject malformed
        // aliases without ever destroying an existing borrowed reference.
        if item.handle != H::default()
            && !borrowed.contains(&item.handle)
            && !handles
                .iter()
                .take(index)
                .any(|old| old.handle == item.handle)
        {
            close(item.handle);
        }
    }
}

fn reply<'a, E>(
    response: &'a [u8],
    length: usize,
    handles: usize,
) -> Result<&'a [u8], ClientError<E>> {
    let bytes = response
        .get(..length)
        .ok_or(ClientError::MismatchedResponse)?;
    if let Ok(status) = <[u8; 4]>::try_from(bytes) {
        let status = i32::from_le_bytes(status);
        return Err(if status < 0 && handles == 0 {
            ClientError::Remote(status)
        } else {
            ClientError::MismatchedResponse
        });
    }
    Ok(bytes)
}

/// Start one atomic send through a socket or a prepared per-call route's WRITE
/// authority. The caller owns the returned transaction and must
/// close it after commit or abort; closing an uncommitted job drops all stages.
pub fn begin<T: ObjectTransport>(
    transport: &T,
    socket: Handle<T::Handle>,
    length: u32,
    descriptors: u16,
    mut close: impl FnMut(T::Handle),
) -> Result<Handle<T::Handle>, ClientError<T::Error>>
where
    T::Handle: Default + Eq,
{
    let request = wire::begin(length, descriptors).map_err(ClientError::Protocol)?;
    let mut handles = ObjectHandles::new();
    attach::<T>(&mut handles, socket, mnu_abi::HANDLE_RIGHT_WRITE)?;
    let mut response = [0; 4];
    let result = transport
        .call_with_handles(&request, &mut response, &mut handles)
        .map_err(ClientError::Transport);
    if matches!(result, Ok(4)) && i32::from_le_bytes(response) == 0 && handles.len() == 1 {
        let job = handles.get(0).unwrap();
        if job.handle != T::Handle::default()
            && job.handle != socket.handle
            && job.rights == wire::RIGHTS
        {
            return Ok(job);
        }
    }
    cleanup(&handles, &[socket.handle], &mut close);
    Err(match result {
        Err(error) => error,
        Ok(4) if handles.is_empty() && i32::from_le_bytes(response) < 0 => {
            ClientError::Remote(i32::from_le_bytes(response))
        }
        _ => ClientError::MismatchedResponse,
    })
}

fn status<T: ObjectTransport>(
    transport: &T,
    request: &[u8],
    handles: &mut ObjectHandles<T::Handle>,
    minimum: u32,
    maximum: u32,
    mut close: impl FnMut(T::Handle),
) -> Result<u32, ClientError<T::Error>>
where
    T::Handle: Default + Eq,
{
    let mut borrowed = [T::Handle::default(); crate::MAX_OBJECT_HANDLES];
    for (target, item) in borrowed.iter_mut().zip(handles.iter()) {
        *target = item.handle;
    }
    let mut response = [0; 4];
    let result = transport
        .call_with_handles(request, &mut response, handles)
        .map_err(ClientError::Transport);
    let unexpected = !handles.is_empty();
    cleanup(handles, &borrowed, &mut close);
    let count = result?;
    if count != 4 || unexpected {
        return Err(ClientError::MismatchedResponse);
    }
    let value = i32::from_le_bytes(response);
    if value < 0 {
        return Err(ClientError::Remote(value));
    }
    if (value as u32) < minimum || value as u32 > maximum {
        return Err(ClientError::MismatchedResponse);
    }
    Ok(value as u32)
}

/// Append one ordered batch. Borrowed sources must stay alive through this
/// call. Descriptor-local flags are stripped, never inherited by the receiver.
/// On any error abort the transaction; do not replay an ambiguous IPC result.
pub fn append<T: ObjectTransport>(
    transport: &T,
    job: Handle<T::Handle>,
    offset: u16,
    files: &[SendFile<T::Handle>],
    close: impl FnMut(T::Handle),
) -> Result<(), ClientError<T::Error>>
where
    T::Handle: Default + Eq,
{
    if files.is_empty() || files.len() > wire::BATCH_SIZE {
        return Err(ClientError::Protocol(
            mochios_posix_protocol::ProtocolError::InvalidLength,
        ));
    }
    let metadata = core::array::from_fn::<_, { wire::BATCH_SIZE }, _>(|index| {
        let mut info = files[index.min(files.len() - 1)].metadata;
        info.descriptor_flags = 0;
        info
    });
    let mut request = [0; wire::MAX_REQUEST_LEN];
    let count = wire::append(offset, &metadata[..files.len()], &mut request)
        .map_err(ClientError::Protocol)?;
    let mut handles = ObjectHandles::new();
    attach::<T>(&mut handles, job, mnu_abi::HANDLE_RIGHT_CONTROL)?;
    for file in files {
        if file.object.handle == job.handle || file.object.rights & !mnu_abi::HANDLE_RIGHT_ALL != 0
        {
            return Err(ClientError::Remote(-13));
        }
        // No extra READ/WRITE/DUPLICATE authority is required to pass a file.
        attach::<T>(&mut handles, file.object, file.object.rights)?;
    }
    status(
        transport,
        &request[..count],
        &mut handles,
        offset as u32 + files.len() as u32,
        offset as u32 + files.len() as u32,
        close,
    )
    .map(|_| ())
}

/// Commit a complete datagram plus staged references once. For a byte stream
/// use commit_prefix instead. Only an explicit remote EAGAIN
/// permits retrying this same job; a transport failure is ambiguous and must
/// abort. The source RAM is borrowed and only READ|MAP is attached.
pub fn commit<T: ObjectTransport>(
    transport: &T,
    job: Handle<T::Handle>,
    buffer: Handle<T::Handle>,
    offset: u64,
    length: u32,
    close: impl FnMut(T::Handle),
) -> Result<(), ClientError<T::Error>>
where
    T::Handle: Default + Eq,
{
    let count = commit_prefix(transport, job, buffer, offset, length, close)?;
    if count != length {
        return Err(ClientError::MismatchedResponse);
    }
    Ok(())
}

/// A byte-stream send may commit a nonempty prefix. Its rights are transferred
/// with that prefix, not retained for resending the unwritten tail.
pub fn commit_prefix<T: ObjectTransport>(
    transport: &T,
    job: Handle<T::Handle>,
    buffer: Handle<T::Handle>,
    offset: u64,
    length: u32,
    close: impl FnMut(T::Handle),
) -> Result<u32, ClientError<T::Error>>
where
    T::Handle: Default + Eq,
{
    if length > wire::MAX_PAYLOAD_LEN
        || offset.checked_add(length as u64).is_none()
        || job.handle == buffer.handle
    {
        return Err(ClientError::Protocol(
            mochios_posix_protocol::ProtocolError::InvalidLength,
        ));
    }
    let mut handles = ObjectHandles::new();
    attach::<T>(&mut handles, job, mnu_abi::HANDLE_RIGHT_CONTROL)?;
    attach::<T>(
        &mut handles,
        buffer,
        mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_MAP,
    )?;
    status(
        transport,
        &wire::commit(offset),
        &mut handles,
        u32::from(length != 0),
        length,
        close,
    )
}

/// Consume one datagram or stream prefix into an explicit RAM object. Reserve
/// local FD/control capacity first and pass that bound as `maximum_rights`.
/// No retry is safe after an ambiguous transport error: the record may already
/// have been consumed. `response` holds the returned source address's storage.
pub fn receive<'a, T: ObjectTransport>(
    transport: &T,
    socket: Handle<T::Handle>,
    buffer: Handle<T::Handle>,
    offset: u64,
    length: u32,
    maximum_rights: u16,
    response: &'a mut [u8],
    mut close: impl FnMut(T::Handle),
) -> Result<Received<'a, T::Handle>, ClientError<T::Error>>
where
    T::Handle: Default + Eq,
{
    let request = wire::receive(offset, length, maximum_rights).map_err(ClientError::Protocol)?;
    if socket.handle == buffer.handle || response.len() < wire::MAX_RECEIVE_REPLY_LEN {
        return Err(ClientError::MismatchedResponse);
    }
    let mut handles = ObjectHandles::new();
    attach::<T>(&mut handles, socket, mnu_abi::HANDLE_RIGHT_READ)?;
    attach::<T>(
        &mut handles,
        buffer,
        mnu_abi::HANDLE_RIGHT_WRITE | mnu_abi::HANDLE_RIGHT_MAP,
    )?;
    let result = (|response: &'a mut [u8]| {
        let count = transport
            .call_with_handles(&request, response, &mut handles)
            .map_err(ClientError::Transport)?;
        let bytes = reply(response, count, handles.len())?;
        let message = wire::ReceiveReply::decode(length, maximum_rights, bytes)
            .map_err(ClientError::Protocol)?;
        let expected = usize::from(message.available_rights != 0);
        if handles.len() != expected {
            return Err(ClientError::MismatchedResponse);
        }
        let receipt = handles.get(0);
        if receipt.is_some_and(|item| {
            item.handle == T::Handle::default()
                || item.handle == socket.handle
                || item.handle == buffer.handle
                || item.rights != wire::RIGHTS
        }) {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(Received { message, receipt })
    })(response);
    if result.is_err() {
        cleanup(&handles, &[socket.handle, buffer.handle], &mut close);
    }
    result
}

/// Collect one ordered batch from a receipt. `offset` counts already delivered
/// references, not FD numbers. On error all newly received references are
/// closed; the caller must abort the receipt, not retry an ambiguous delivery.
pub fn deliver<T: ObjectTransport>(
    transport: &T,
    receipt: Handle<T::Handle>,
    offset: u16,
    maximum: u16,
    mut close: impl FnMut(T::Handle),
) -> Result<Delivery<T::Handle>, ClientError<T::Error>>
where
    T::Handle: Default + Eq,
{
    let request = wire::deliver(offset, maximum).map_err(ClientError::Protocol)?;
    let mut handles = ObjectHandles::new();
    attach::<T>(&mut handles, receipt, mnu_abi::HANDLE_RIGHT_CONTROL)?;
    let mut response = [0; wire::MAX_DELIVERY_REPLY_LEN];
    let result = (|| {
        let size = transport
            .call_with_handles(&request, &mut response, &mut handles)
            .map_err(ClientError::Transport)?;
        let bytes = reply(&response, size, handles.len())?;
        let (metadata, count) =
            wire::decode_delivery(offset, maximum, bytes).map_err(ClientError::Protocol)?;
        if count != handles.len()
            || handles.iter().enumerate().any(|(index, item)| {
                item.handle == T::Handle::default()
                    || item.handle == receipt.handle
                    || item.rights & mnu_abi::HANDLE_RIGHT_TRANSFER == 0
                    || item.rights & !mnu_abi::HANDLE_RIGHT_ALL != 0
                    || handles
                        .iter()
                        .take(index)
                        .any(|old| old.handle == item.handle)
            })
        {
            return Err(ClientError::MismatchedResponse);
        }
        let files = core::array::from_fn(|index| {
            handles.get(index).map(|object| ReceivedFile {
                object,
                metadata: metadata[index].unwrap(),
            })
        });
        Ok(Delivery { files, count })
    })();
    if result.is_err() {
        cleanup(&handles, &[receipt.handle], &mut close);
    }
    result
}
