//! Boot manager control, separate from client socket authority acquisition.
use crate::{Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport};
use mochios_posix_protocol as protocol;
impl<T: ObjectTransport> Client<T> {
    /// Obtain only a callable endpoint. The network service authenticates the
    /// actual caller when the caller subsequently acquires a factory.
    pub fn network_endpoint(
        &self,
        mut close: impl FnMut(T::Handle),
    ) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        let borrowed = handles.clone();
        let result = self.request_with_handles(
            protocol::OP_NETWORK_ENDPOINT_GET,
            0,
            &[],
            &mut [],
            &mut handles,
        );
        if matches!(result, Ok(0)) && handles.len() == 1 {
            let handle = handles.get(0).unwrap();
            if handle.handle != T::Handle::default()
                && handle.rights == protocol::network::client_endpoint_rights()
            {
                return Ok(handle);
            }
        }
        crate::drain_received_handles(&mut handles, &borrowed, &mut close);
        Err(result.err().unwrap_or(ClientError::MismatchedResponse))
    }
    /// The endpoint is borrowed. Only the native-authenticated bootstrap
    /// process may install it. Receiving it never grants network Capability.
    pub fn install_network_endpoint(
        &self,
        endpoint: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        let rights = protocol::network::endpoint_rights();
        if endpoint.handle == T::Handle::default() || endpoint.rights & rights != rights {
            return Err(ClientError::Remote(-13));
        }
        let mut handles = ObjectHandles::new();
        handles
            .push(ObjectHandleAttachment {
                handle: endpoint.handle,
                rights,
            })
            .map_err(|_| ClientError::RequestTooLarge)?;
        let borrowed = handles.clone();
        let result = self.request_with_handles(
            protocol::OP_NETWORK_ENDPOINT_INSTALL,
            0,
            &[],
            &mut [],
            &mut handles,
        );
        let valid = matches!(result, Ok(0)) && handles.is_empty();
        crate::drain_received_handles(&mut handles, &borrowed, |handle| {
            self.transport.close_received_handle(handle)
        });
        if valid {
            Ok(())
        } else {
            Err(result.err().unwrap_or(ClientError::MismatchedResponse))
        }
    }
}

/// Invoke the explicitly held endpoint as this process. No service-name
/// discovery or POSIX-service CapabilitySet impersonation is involved.
pub fn acquire_factory<T: ObjectTransport>(
    transport: &T,
    mut close: impl FnMut(T::Handle),
) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
    use mochios_net_device_protocol::datagram_authority as wire;
    let mut response = [0; wire::REPLY_LEN];
    let mut handles = ObjectHandles::new();
    let borrowed = handles.clone();
    let result = transport
        .call_with_handles(&wire::ACQUIRE, &mut response, &mut handles)
        .map_err(ClientError::Transport);
    let checked = (|| {
        let n = result?;
        let status = wire::status(response.get(..n).ok_or(ClientError::MismatchedResponse)?)
            .map_err(|_| ClientError::MismatchedResponse)?;
        if status != 0 {
            return Err(ClientError::Remote(status));
        }
        if handles.len() != 1 {
            return Err(ClientError::MismatchedResponse);
        }
        let object = handles.get(0).unwrap();
        let rights = mnu_abi::HANDLE_RIGHT_CONTROL
            | mnu_abi::HANDLE_RIGHT_DUPLICATE
            | mnu_abi::HANDLE_RIGHT_TRANSFER;
        if object.handle == T::Handle::default() || object.rights != rights {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(object)
    })();
    if checked.is_err() {
        crate::drain_received_handles(&mut handles, &borrowed, &mut close);
    }
    checked
}

/// Scope bits describe delegated resource authority, not POSIX uid privileges.
pub use mochios_net_device_protocol::stream::{CONNECT_SCOPE, LISTEN_SCOPE};

pub fn acquire_stream_factory<T: ObjectTransport>(
    transport: &T,
    scopes: u32,
    mut close: impl FnMut(T::Handle),
) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
    use mochios_net_device_protocol::stream as wire;
    let request = wire::scoped(wire::ACQUIRE, scopes).map_err(|_| ClientError::Remote(-22))?;
    let mut response = [0; wire::REPLY_LEN];
    let mut handles = ObjectHandles::new();
    let borrowed = handles.clone();
    let outcome = transport
        .call_with_handles(&request, &mut response, &mut handles)
        .map_err(ClientError::Transport);
    let result = (|| {
        let n = outcome?;
        let status = wire::status(
            wire::ACQUIRE,
            response.get(..n).ok_or(ClientError::MismatchedResponse)?,
        )
        .map_err(|_| ClientError::MismatchedResponse)?;
        if status != 0 {
            return Err(ClientError::Remote(status));
        }
        if handles.len() != 1 {
            return Err(ClientError::MismatchedResponse);
        }
        let object = handles.get(0).unwrap();
        let rights = mnu_abi::HANDLE_RIGHT_CONTROL
            | mnu_abi::HANDLE_RIGHT_DUPLICATE
            | mnu_abi::HANDLE_RIGHT_TRANSFER;
        if object.handle == T::Handle::default() || object.rights != rights {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(object)
    })();
    if result.is_err() {
        crate::drain_received_handles(&mut handles, &borrowed, &mut close);
    }
    result
}
