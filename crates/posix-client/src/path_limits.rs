use super::*;
use mochios_filesystem_protocol::object_limits;

impl<T: ObjectTransport> Client<T> {
    pub fn path_limits_at(
        &self,
        base: StatAtBase<T::Handle>,
        path: impl AsRef<[u8]>,
    ) -> Result<object_limits::Limits, ClientError<T::Error>> {
        let mut response = [0; object_limits::RESPONSE_LEN];
        let length =
            self.configuration_at(base, path, protocol::OP_PATH_LIMITS_AT, &mut response)?;
        response
            .get(..length)
            .and_then(object_limits::Limits::decode)
            .ok_or(ClientError::MismatchedResponse)
    }

    pub fn terminal_limits_at(
        &self,
        base: StatAtBase<T::Handle>,
        path: impl AsRef<[u8]>,
    ) -> Result<protocol::terminal_limits::Limits, ClientError<T::Error>> {
        let mut response = [0; protocol::terminal_limits::RESPONSE_LEN];
        let length =
            self.configuration_at(base, path, protocol::OP_TERMINAL_LIMITS_AT, &mut response)?;
        protocol::terminal_limits::Limits::decode(
            response
                .get(..length)
                .ok_or(ClientError::MismatchedResponse)?,
        )
        .map_err(ClientError::Protocol)
    }

    pub(super) fn configuration_at(
        &self,
        base: StatAtBase<T::Handle>,
        path: impl AsRef<[u8]>,
        opcode: u16,
        response: &mut [u8],
    ) -> Result<usize, ClientError<T::Error>> {
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
        self.request_without_reply_handles(opcode, &payload[..length], response, &mut handles)
    }
}
