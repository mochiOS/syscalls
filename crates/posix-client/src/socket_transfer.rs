//! Ancillary receive over the dedicated socket worker endpoint. FD numbers
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

/// Consume one datagram, copying data into an explicit RAM object. Reserve
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
