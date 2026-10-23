//! Process-owned timer controls. The inherited endpoint supplies identity;
//! scalar timer IDs never select another process or native object.
use super::*;
use protocol::process_timer as wire;
pub use wire::{Clock, Notification, Value};

impl<T: ObjectTransport> Client<T> {
    fn timer_request(
        &self,
        opcode: u16,
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize, ClientError<T::Error>> {
        self.request_without_reply_handles(opcode, payload, output, &mut ObjectHandles::new())
    }

    /// Notifying modes currently return ENOSYS until the service's reactor
    /// delivery adapter is connected; they are never silently dropped.
    pub fn timer_create(
        &self,
        clock: Clock,
        notification: Notification,
    ) -> Result<u64, ClientError<T::Error>> {
        let mut input = [0; wire::CREATE_LEN];
        wire::encode_create(clock, notification, &mut input).map_err(ClientError::Protocol)?;
        let mut output = [0; 8];
        let length = self.timer_request(protocol::OP_TIMER_CREATE, &input, &mut output)?;
        wire::decode_id(&output[..length]).map_err(ClientError::Protocol)
    }

    pub fn timer_delete(&self, id: u64) -> Result<(), ClientError<T::Error>> {
        let input = id.to_le_bytes();
        wire::decode_id(&input).map_err(ClientError::Protocol)?;
        let length = self.timer_request(protocol::OP_TIMER_DELETE, &input, &mut [])?;
        if length != 0 {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    pub fn timer_value(&self, id: u64) -> Result<Value, ClientError<T::Error>> {
        let input = id.to_le_bytes();
        wire::decode_id(&input).map_err(ClientError::Protocol)?;
        let mut output = [0; wire::VALUE_LEN];
        let length = self.timer_request(protocol::OP_TIMER_GET, &input, &mut output)?;
        wire::decode_value(&output[..length]).map_err(ClientError::Protocol)
    }

    pub fn timer_set(
        &self,
        id: u64,
        absolute: bool,
        value: Value,
    ) -> Result<Value, ClientError<T::Error>> {
        let mut input = [0; wire::SET_LEN];
        wire::encode_set(id, absolute, value, &mut input).map_err(ClientError::Protocol)?;
        let mut output = [0; wire::VALUE_LEN];
        let length = self.timer_request(protocol::OP_TIMER_SET, &input, &mut output)?;
        wire::decode_value(&output[..length]).map_err(ClientError::Protocol)
    }

    pub fn timer_overrun(&self, id: u64) -> Result<u32, ClientError<T::Error>> {
        let input = id.to_le_bytes();
        wire::decode_id(&input).map_err(ClientError::Protocol)?;
        let mut output = [0; 4];
        let length = self.timer_request(protocol::OP_TIMER_OVERRUN, &input, &mut output)?;
        if length != output.len() {
            return Err(ClientError::Protocol(
                protocol::ProtocolError::InvalidLength,
            ));
        }
        let value = u32::from_le_bytes(output);
        if value > i32::MAX as u32 {
            return Err(ClientError::Protocol(
                protocol::ProtocolError::InvalidLength,
            ));
        }
        Ok(value)
    }
}
