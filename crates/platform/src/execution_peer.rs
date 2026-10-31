//! Capture the measured native owner of an IPC endpoint. Endpoint/Process
//! observations must agree across image commits; no caller-asserted PID is used.
use crate::{handle, ipc, process, syscall};
use syscall::{NativeError, ProcessImageInfo, SysError, ThreadSecurityContext};

pub struct ProcessReference(pub u32);
impl Drop for ProcessReference {
    fn drop(&mut self) {
        let _ = handle::close(self.0);
    }
}

pub struct MeasuredPeer {
    pub endpoint: u64,
    pub context: ThreadSecurityContext,
    pub image: ProcessImageInfo,
    pub process: ProcessReference,
}

fn denied() -> SysError {
    SysError::from_raw(NativeError::AccessDenied.into_raw() as i64)
}

pub fn capture(endpoint: u64) -> Result<MeasuredPeer, SysError> {
    if endpoint == 0 {
        return Err(denied());
    }
    let first = ipc::endpoint_execution_identity(endpoint)?;
    let process = ProcessReference(process::open_handle_for_endpoint(
        endpoint,
        handle::HANDLE_RIGHT_WAIT,
    )?);
    let before = process::image_info(Some(process.0))?;
    let context = process::thread_security_context(endpoint)?;
    let after = process::image_info(Some(process.0))?;
    let last = ipc::endpoint_execution_identity(endpoint)?;
    if first != last
        || first.process_id == 0
        || first.thread_id == 0
        || first.process_id != before.process_id
        || before != after
        || after.digest_kind != syscall::PROCESS_IMAGE_DIGEST_SHA256
        || context.process_id != first.process_id
        || context.thread_id != first.thread_id
        || context.reserved0 != [0; 7]
        || context.reserved1 != 0
        || context.package_id_len as usize > context.package_id.len()
        || context.developer_id_len as usize > context.developer_id.len()
    {
        return Err(denied());
    }
    Ok(MeasuredPeer {
        endpoint,
        context,
        image: after,
        process,
    })
}
