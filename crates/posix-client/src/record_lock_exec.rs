use super::*;
use protocol::record_lock_exec as wire;

impl<T: ObjectTransport> Client<T> {
    /// Register one bounded batch of files that the proposed exec will close.
    /// Callers must serialize exec/FD/lock changes and cancel on failure.
    /// `None` means this initial batch contained no caller-owned locked file.
    pub fn prepare_record_lock_exec(
        &self,
        files: &[ObjectHandleAttachment<T::Handle>],
        previous: Option<u64>,
    ) -> Result<Option<u64>, ClientError<T::Error>> {
        if files.is_empty() || files.len() > MAX_OBJECT_HANDLES || previous == Some(0) {
            return Err(ClientError::Protocol(
                protocol::ProtocolError::InvalidLength,
            ));
        }
        let mut attached = ObjectHandles::new();
        for file in files {
            let rights = mnu_abi::HANDLE_RIGHT_TRANSFER;
            if file.rights & rights != rights {
                return Err(ClientError::Remote(-13));
            }
            attached
                .push(ObjectHandleAttachment {
                    handle: file.handle,
                    rights,
                })
                .map_err(|_| ClientError::RequestTooLarge)?;
        }
        let mut payload = [0; wire::LEN];
        wire::encode(wire::Request::Prepare(previous.unwrap_or(0)), &mut payload)
            .map_err(ClientError::Protocol)?;
        let mut reply = [0; wire::LEN];
        let length = self.request_without_reply_handles(
            protocol::OP_RECORD_LOCK_EXEC,
            &payload,
            &mut reply,
            &mut attached,
        )?;
        let token = wire::decode_reply(&reply[..length]).map_err(ClientError::Protocol)?;
        if previous.is_some_and(|previous| previous != token) {
            return Err(ClientError::MismatchedResponse);
        }
        Ok((token != 0).then_some(token))
    }

    pub fn cancel_record_lock_exec(&self, token: u64) -> Result<(), ClientError<T::Error>> {
        let mut payload = [0; wire::LEN];
        wire::encode(wire::Request::Cancel(token), &mut payload).map_err(ClientError::Protocol)?;
        let mut reply = [0; wire::LEN];
        let length = self.request_without_reply_handles(
            protocol::OP_RECORD_LOCK_EXEC,
            &payload,
            &mut reply,
            &mut ObjectHandles::new(),
        )?;
        match wire::decode_reply(&reply[..length]).map_err(ClientError::Protocol)? {
            0 => Ok(()),
            _ => Err(ClientError::MismatchedResponse),
        }
    }
}
