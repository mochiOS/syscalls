//! Admission only. The caller owns the completion Handle and waits using
//! native events, so no CPU clock polling or signal reservation is needed.
use super::*;
use protocol::cpu_sleep as wire;

pub struct Pending<H> {
    pub completion: ObjectHandleAttachment<H>,
    pub deadline_ns: u128,
}

impl<T: ObjectTransport> Client<T> {
    pub fn begin_process_cpu_sleep(
        &self,
        request: wire::Request,
    ) -> Result<Pending<T::Handle>, ClientError<T::Error>> {
        let mut input = [0; wire::REQUEST_LEN];
        wire::encode_request(request, &mut input).map_err(ClientError::Protocol)?;
        let mut output = [0; wire::REPLY_LEN];
        let mut handles = ObjectHandles::new();
        let result = self
            .request_with_handles(
                protocol::OP_PROCESS_CPU_SLEEP,
                0,
                &input,
                &mut output,
                &mut handles,
            )
            .and_then(|length| {
                let deadline_ns =
                    wire::decode_reply(&output[..length]).map_err(ClientError::Protocol)?;
                let completion = handles
                    .get(0)
                    .filter(|handle| {
                        handles.len() == 1
                            && handle.handle != T::Handle::default()
                            && handle.rights == wire::COMPLETION_RIGHTS
                    })
                    .ok_or(ClientError::MismatchedResponse)?;
                Ok(Pending {
                    completion,
                    deadline_ns,
                })
            });
        if result.is_ok() {
            handles.clear();
        } else {
            self.discard_received_handles(&mut handles, &ObjectHandles::new());
        }
        result
    }
}
