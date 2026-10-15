use super::*;

impl<T: ObjectTransport> Client<T> {
    /// Prepare inherited policy before capturing VM. No caller identity is
    /// serialized: authentication comes exclusively from the IPC sender.
    pub fn prepare_fork(&self) -> Result<u64, ClientError<T::Error>> {
        let mut response = [0; protocol::fork::TOKEN_LEN];
        let length = self.request_without_reply_handles(
            protocol::OP_FORK_PREPARE,
            &[],
            &mut response,
            &mut ObjectHandles::new(),
        )?;
        protocol::fork::decode_token(&response[..length]).map_err(ClientError::Protocol)
    }

    /// The child must remain stopped until this succeeds. On an ambiguous
    /// commit failure retain its ProcessHandle and use launch-abort cleanup.
    pub fn commit_fork(
        &self,
        token: u64,
        process: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        let mut payload = [0; protocol::fork::TOKEN_LEN];
        protocol::fork::encode_token(token, &mut payload).map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        handles
            .push(process)
            .map_err(|_| ClientError::RequestTooLarge)?;
        self.request_without_reply_handles(
            protocol::OP_FORK_COMMIT,
            &payload,
            &mut [],
            &mut handles,
        )?;
        Ok(())
    }

    pub fn cancel_fork(&self, token: u64) -> Result<(), ClientError<T::Error>> {
        let mut payload = [0; protocol::fork::TOKEN_LEN];
        protocol::fork::encode_token(token, &mut payload).map_err(ClientError::Protocol)?;
        self.request_without_reply_handles(
            protocol::OP_FORK_CANCEL,
            &payload,
            &mut [],
            &mut ObjectHandles::new(),
        )?;
        Ok(())
    }
}
