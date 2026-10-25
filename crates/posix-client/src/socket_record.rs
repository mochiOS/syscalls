//! Direct socket-worker data calls. Only endpoint acquisition uses the main
//! POSIX dispatcher. Every data/wait request attaches attenuated authority.
use crate::{
    Client, ClientError, ObjectHandleAttachment as Handle, ObjectHandles, ObjectTransport,
};
use mochios_posix_protocol::{self as protocol, socket_record as wire};

fn cleanup<H: Copy + Default + Eq>(handles: &ObjectHandles<H>, mut close: impl FnMut(H)) {
    for (index, received) in handles.iter().enumerate() {
        if received.handle != H::default()
            && !handles
                .iter()
                .take(index)
                .any(|old| old.handle == received.handle)
        {
            close(received.handle);
        }
    }
}

impl<T: ObjectTransport> Client<T>
where
    T::Handle: Default + Eq,
{
    pub fn socket_record_endpoint(
        &self,
        mut close: impl FnMut(T::Handle),
    ) -> Result<Handle<T::Handle>, ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        let result = self.request_with_handles(
            protocol::OP_SOCKET_RECORD_ENDPOINT,
            0,
            &[],
            &mut [],
            &mut handles,
        );
        if matches!(result, Ok(0)) && handles.len() == 1 {
            let endpoint = handles.get(0).unwrap();
            if endpoint.handle != T::Handle::default() && endpoint.rights == wire::ENDPOINT_RIGHTS {
                return Ok(endpoint);
            }
        }
        cleanup(&handles, &mut close);
        Err(result.err().unwrap_or(ClientError::MismatchedResponse))
    }
}

fn attach<T: ObjectTransport>(
    handles: &mut ObjectHandles<T::Handle>,
    source: Handle<T::Handle>,
    rights: u64,
) -> Result<(), ClientError<T::Error>>
where
    T::Handle: Default + Eq,
{
    if source.handle == T::Handle::default()
        || source.rights & (rights | mnu_abi::HANDLE_RIGHT_TRANSFER)
            != rights | mnu_abi::HANDLE_RIGHT_TRANSFER
    {
        return Err(ClientError::Remote(-13));
    }
    handles
        .push(Handle {
            handle: source.handle,
            rights,
        })
        .map_err(|_| ClientError::RequestTooLarge)
}

pub fn exchange<'a, T: ObjectTransport>(
    transport: &T,
    request: wire::Request,
    socket: Handle<T::Handle>,
    buffer: Handle<T::Handle>,
    response: &'a mut [u8],
    mut close: impl FnMut(T::Handle),
) -> Result<wire::Reply<'a>, ClientError<T::Error>>
where
    T::Handle: Default + Eq,
{
    if request.operation == wire::Operation::WaitSend {
        return Err(ClientError::Remote(-22));
    }
    let bytes = request.encode().map_err(ClientError::Protocol)?;
    exchange_frame(transport, request, &bytes, socket, buffer, response, close)
}
pub fn send_to<'a, T: ObjectTransport>(
    transport: &T,
    request: wire::Request,
    address: protocol::socket::Address<'_>,
    socket: Handle<T::Handle>,
    buffer: Handle<T::Handle>,
    response: &'a mut [u8],
    close: impl FnMut(T::Handle),
) -> Result<wire::Reply<'a>, ClientError<T::Error>> {
    let mut bytes = [0; wire::REQUEST_LEN + protocol::socket::MAX_ADDRESS_LEN];
    let n = wire::encode_send_to(request, address, &mut bytes).map_err(ClientError::Protocol)?;
    exchange_frame(
        transport,
        request,
        &bytes[..n],
        socket,
        buffer,
        response,
        close,
    )
}
fn exchange_frame<'a, T: ObjectTransport>(
    transport: &T,
    request: wire::Request,
    bytes: &[u8],
    socket: Handle<T::Handle>,
    buffer: Handle<T::Handle>,
    response: &'a mut [u8],
    mut close: impl FnMut(T::Handle),
) -> Result<wire::Reply<'a>, ClientError<T::Error>> {
    let mut handles = ObjectHandles::new();
    attach::<T>(&mut handles, socket, request.socket_rights())?;
    attach::<T>(&mut handles, buffer, request.buffer_rights())?;
    let result = transport
        .call_with_handles(&bytes, response, &mut handles)
        .map_err(ClientError::Transport);
    let unexpected = !handles.is_empty();
    cleanup(&handles, &mut close);
    let length = result?;
    if unexpected {
        return Err(ClientError::MismatchedResponse);
    }
    let response = response
        .get(..length)
        .ok_or(ClientError::MismatchedResponse)?;
    if response.len() == 4 {
        let status = i32::from_le_bytes(response.try_into().unwrap());
        return Err(if status < 0 {
            ClientError::Remote(status)
        } else {
            ClientError::MismatchedResponse
        });
    }
    wire::Reply::decode(request, response).map_err(ClientError::Protocol)
}

pub fn wait_send<T: ObjectTransport>(
    transport: &T,
    socket: Handle<T::Handle>,
    length: usize,
    mut close: impl FnMut(T::Handle),
) -> Result<Handle<T::Handle>, ClientError<T::Error>>
where
    T::Handle: Default + Eq,
{
    let request = wire::Request {
        operation: wire::Operation::WaitSend,
        offset: 0,
        length: u32::try_from(length).map_err(|_| ClientError::Remote(-90))?,
        peek: false,
    };
    let bytes = request.encode().map_err(ClientError::Protocol)?;
    let mut handles = ObjectHandles::new();
    attach::<T>(&mut handles, socket, request.socket_rights())?;
    let mut response = [0; 4];
    let result = transport
        .call_with_handles(&bytes, &mut response, &mut handles)
        .map_err(ClientError::Transport);
    if matches!(result, Ok(4)) && i32::from_le_bytes(response) == 0 && handles.len() == 1 {
        let job = handles.get(0).unwrap();
        if job.handle != T::Handle::default()
            && job.handle != socket.handle
            && job.rights == protocol::socket::receive_wait_job_rights()
        {
            return Ok(job);
        }
    }
    cleanup(&handles, &mut close);
    Err(match result {
        Err(error) => error,
        Ok(4) if i32::from_le_bytes(response) < 0 && handles.is_empty() => {
            ClientError::Remote(i32::from_le_bytes(response))
        }
        _ => ClientError::MismatchedResponse,
    })
}

/// Resolve one call's explicit destination without changing the socket's
/// default peer. The owned route is WRITE/WAIT only and must be closed on all
/// exits, including failed staging, timeout and cancellation.
pub fn prepare_route<T: ObjectTransport>(
    transport: &T,
    socket: Handle<T::Handle>,
    length: usize,
    address: protocol::socket::Address<'_>,
    mut close: impl FnMut(T::Handle),
) -> Result<Handle<T::Handle>, ClientError<T::Error>>
where
    T::Handle: Default + Eq,
{
    let mut request = [0; protocol::socket_route::MAX_REQUEST_LEN];
    let length = u32::try_from(length).map_err(|_| ClientError::Remote(-90))?;
    let count = protocol::socket_route::encode(length, address, &mut request)
        .map_err(ClientError::Protocol)?;
    let mut handles = ObjectHandles::new();
    attach::<T>(&mut handles, socket, mnu_abi::HANDLE_RIGHT_WRITE)?;
    let mut response = [0; 4];
    let result = transport
        .call_with_handles(&request[..count], &mut response, &mut handles)
        .map_err(ClientError::Transport);
    if matches!(result, Ok(4)) && i32::from_le_bytes(response) == 0 && handles.len() == 1 {
        let route = handles.get(0).unwrap();
        if route.handle != T::Handle::default()
            && route.handle != socket.handle
            && route.rights == protocol::socket_route::RIGHTS
        {
            return Ok(route);
        }
    }
    cleanup(&handles, &mut close);
    Err(match result {
        Err(error) => error,
        Ok(4) if i32::from_le_bytes(response) < 0 && handles.is_empty() => {
            ClientError::Remote(i32::from_le_bytes(response))
        }
        _ => ClientError::MismatchedResponse,
    })
}
