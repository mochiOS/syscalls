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
        self.begin_cpu_sleep(
            protocol::OP_PROCESS_CPU_SLEEP,
            request,
            ObjectHandles::new(),
        )
    }

    pub fn begin_thread_cpu_sleep(
        &self,
        thread: T::Handle,
        absolute: bool,
        nanoseconds: u128,
    ) -> Result<Pending<T::Handle>, ClientError<T::Error>> {
        if thread == T::Handle::default() {
            return Err(ClientError::MismatchedResponse);
        }
        let mut handles = ObjectHandles::new();
        handles
            .push(ObjectHandleAttachment {
                handle: thread,
                rights: mnu_abi::HANDLE_RIGHT_WAIT,
            })
            .map_err(|_| ClientError::MismatchedResponse)?;
        self.begin_cpu_sleep(
            protocol::OP_THREAD_CPU_SLEEP,
            wire::Request {
                process: 0,
                absolute,
                nanoseconds,
            },
            handles,
        )
    }

    fn begin_cpu_sleep(
        &self,
        opcode: u16,
        request: wire::Request,
        mut handles: ObjectHandles<T::Handle>,
    ) -> Result<Pending<T::Handle>, ClientError<T::Error>> {
        let mut input = [0; wire::REQUEST_LEN];
        wire::encode_request(request, &mut input).map_err(ClientError::Protocol)?;
        let mut output = [0; wire::REPLY_LEN];
        let borrowed = handles.clone();
        let result = self
            .request_with_handles(opcode, 0, &input, &mut output, &mut handles)
            .and_then(|length| {
                let deadline_ns =
                    wire::decode_reply(&output[..length]).map_err(ClientError::Protocol)?;
                let completion = handles
                    .get(0)
                    .filter(|handle| {
                        handles.len() == 1
                            && handle.handle != T::Handle::default()
                            && handle.rights == wire::COMPLETION_RIGHTS
                            && !borrowed.iter().any(|source| source.handle == handle.handle)
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
            self.discard_received_handles(&mut handles, &borrowed);
        }
        result
    }
}
