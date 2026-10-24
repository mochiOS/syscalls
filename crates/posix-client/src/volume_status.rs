use super::*;
use mochios_filesystem_protocol::volume_status as wire;
impl<T: ObjectTransport> Client<T> {
    pub fn volume_status_at(
        &self,
        base: StatAtBase<T::Handle>,
        path: impl AsRef<[u8]>,
    ) -> Result<wire::Status, ClientError<T::Error>> {
        let mut response = [0; wire::RESPONSE_LEN];
        let length =
            self.configuration_at(base, path, protocol::OP_VOLUME_STATUS_AT, &mut response)?;
        wire::Status::decode(
            response
                .get(..length)
                .ok_or(ClientError::MismatchedResponse)?,
        )
        .ok_or(ClientError::MismatchedResponse)
    }
    pub fn volume_status(
        &self,
        file: ObjectHandleAttachment<T::Handle>,
    ) -> Result<wire::Status, ClientError<T::Error>> {
        if file.handle == T::Handle::default() || file.rights & mnu_abi::HANDLE_RIGHT_TRANSFER == 0
        {
            return Err(ClientError::Remote(-13));
        }
        let mut response = [0; wire::RESPONSE_LEN];
        let length = self.file_request(
            protocol::OP_VOLUME_STATUS_HANDLE,
            &[],
            ObjectHandleAttachment {
                rights: mnu_abi::HANDLE_RIGHT_TRANSFER,
                ..file
            },
            &mut response,
        )?;
        wire::Status::decode(
            response
                .get(..length)
                .ok_or(ClientError::MismatchedResponse)?,
        )
        .ok_or(ClientError::MismatchedResponse)
    }
}
