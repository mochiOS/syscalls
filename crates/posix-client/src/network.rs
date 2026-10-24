//! Boot manager control, separate from client socket authority acquisition.
use crate::{Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport};
use mochios_posix_protocol as protocol;
impl<T: ObjectTransport> Client<T> {
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
