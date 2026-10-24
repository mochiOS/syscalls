//! Wait registrations are the slow path after an unsuccessful native FIFO
//! operation. The caller keeps its data lease alive and owns the returned job.
use crate::{Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport};
use mochios_posix_protocol as wire;
impl<T: ObjectTransport> Client<T> {
    pub fn fifo_wait(
        &self,
        source: ObjectHandleAttachment<T::Handle>,
        condition: wire::fifo::WaitCondition,
    ) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
        let direction = condition
            .source_direction(source.rights)
            .ok_or(ClientError::Remote(-13))?;
        if source.handle == T::Handle::default()
            || source.rights & mnu_abi::HANDLE_RIGHT_TRANSFER == 0
        {
            return Err(ClientError::Remote(-13));
        }
        let payload = condition.encode().map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        handles
            .push(ObjectHandleAttachment {
                rights: direction | mnu_abi::HANDLE_RIGHT_TRANSFER,
                ..source
            })
            .map_err(|_| ClientError::RequestTooLarge)?;
        let borrowed = handles.clone();
        let result =
            self.request_with_handles(wire::OP_FIFO_WAIT, 0, &payload, &mut [], &mut handles);
        if result.is_ok() && handles.len() == 1 {
            let job = handles.get(0).ok_or(ClientError::MismatchedResponse)?;
            if job.handle != T::Handle::default()
                && job.handle != source.handle
                && job.rights == wire::fifo::NOTIFICATION_RIGHTS
            {
                handles.clear();
                return Ok(job);
            }
        }
        self.discard_received_handles(&mut handles, &borrowed);
        result?;
        Err(ClientError::MismatchedResponse)
    }
}
