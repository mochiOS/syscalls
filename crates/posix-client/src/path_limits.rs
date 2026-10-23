use super::*;
use mochios_filesystem_protocol::object_limits;

impl<T: ObjectTransport> Client<T> {
    pub fn path_limits_at(
        &self,
        base: StatAtBase<T::Handle>,
        path: impl AsRef<[u8]>,
    ) -> Result<object_limits::Limits, ClientError<T::Error>> {
        let (base, directory) = match base {
            StatAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
            StatAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
            StatAtBase::Directory(handle) => (protocol::OpenBase::AttachedDirectory, Some(handle)),
        };
        let mut payload = [0; protocol::STAT_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
        let length = protocol::encode_stat_at(
            protocol::StatAtRequest {
                base,
                flags: 0,
                path: path.as_ref(),
            },
            &mut payload,
        )
        .map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        if let Some(directory) = directory {
            handles
                .push(directory)
                .map_err(|_| ClientError::RequestTooLarge)?;
        }
        let mut response = [0; object_limits::RESPONSE_LEN];
        let length = self.request_without_reply_handles(
            protocol::OP_PATH_LIMITS_AT,
            &payload[..length],
            &mut response,
            &mut handles,
        )?;
        response
            .get(..length)
            .and_then(object_limits::Limits::decode)
            .ok_or(ClientError::MismatchedResponse)
    }
}
