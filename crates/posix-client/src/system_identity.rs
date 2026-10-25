use crate::{Client, ClientError, Transport};
use mochios_posix_protocol::{self as protocol, system_identity as wire};

impl<T: Transport> Client<T> {
    pub fn system_identity(&self, output: &mut [u8]) -> Result<usize, ClientError<T::Error>> {
        let size = self.request(protocol::OP_SYSTEM_IDENTITY, 0, &[], output)?;
        wire::decode(&output[..size]).map_err(|_| ClientError::MismatchedResponse)?;
        Ok(size)
    }

    pub fn set_hostname(&self, name: &[u8]) -> Result<(), ClientError<T::Error>> {
        if !wire::valid_field(name) {
            return Err(ClientError::Remote(-22));
        }
        let size = self.request(protocol::OP_HOSTNAME_SET, 0, name, &mut [])?;
        if size != 0 {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }
}
