//! Public account lookup and bootstrap-only endpoint installation.
use crate::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, Transport,
};
use mochios_posix_protocol as protocol;
impl<T: ObjectTransport> Client<T> {
    /// The endpoint is borrowed. Only the native-authenticated bootstrap
    /// process may install it. Public lookup never grants account modification authority.
    pub fn install_account_endpoint(
        &self,
        endpoint: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        let rights = protocol::ACCOUNT_ENDPOINT_RIGHTS;
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
            protocol::OP_ACCOUNT_ENDPOINT_INSTALL,
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
impl<T: Transport> Client<T> {
    pub fn lookup_account(
        &self,
        query: protocol::account::Query<'_>,
        output: &mut [u8],
    ) -> Result<usize, ClientError<T::Error>> {
        let mut request = [0; protocol::account::MAX_QUERY];
        let length = protocol::account::encode_query(query, &mut request)
            .map_err(|_| ClientError::MismatchedResponse)?;
        let length = self.request(protocol::OP_ACCOUNT_LOOKUP, 0, &request[..length], output)?;
        protocol::account::decode_record(&output[..length])
            .map_err(|_| ClientError::MismatchedResponse)?;
        Ok(length)
    }
}
