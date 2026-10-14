//! Socket creation is control-plane IPC. Data, shutdown and readiness use the
//! returned native Provider Handles; client FD numbers never enter the wire.

use crate::{Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport};
use mochios_posix_protocol::{self as protocol, socket as wire};

impl<T: ObjectTransport> Client<T> {
    /// Returns ownership of two receiver-local Handles. The caller must reserve
    /// both local FD slots before requesting resources and close both Handles
    /// if installation fails. `close` releases every attachment on failed or
    /// malformed replies, including owned attachments returned on transport errors.
    pub fn socket_pair(
        &self,
        create: wire::Create,
        mut close: impl FnMut(T::Handle),
    ) -> Result<[ObjectHandleAttachment<T::Handle>; 2], ClientError<T::Error>>
    where
        T::Handle: Eq,
    {
        let mut payload = [0; wire::CREATE_LEN];
        create.encode(&mut payload).map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        let outcome =
            self.request_with_handles(protocol::OP_SOCKET_PAIR, 0, &payload, &mut [], &mut handles);
        if matches!(outcome, Ok(0)) && handles.len() == 2 {
            let first = handles.get(0).unwrap();
            let second = handles.get(1).unwrap();
            if first.rights == wire::descriptor_rights()
                && second.rights == wire::descriptor_rights()
                && first.handle != second.handle
            {
                return Ok([first, second]);
            }
        }
        // ObjectTransport guarantees each returned entry owns a received
        // reference, never a borrowed outgoing Handle (this request has none).
        for (index, received) in handles.iter().enumerate() {
            if !handles
                .iter()
                .take(index)
                .any(|earlier| earlier.handle == received.handle)
            {
                close(received.handle);
            }
        }
        Err(outcome.err().unwrap_or(ClientError::MismatchedResponse))
    }
}
