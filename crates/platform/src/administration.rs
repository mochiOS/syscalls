//! Shared administrator-operation client for native GUI and command clients.
//! Replies carry only the result of this call, never an elevation credential.
use crate::{capability, ipc, syscall};
use zeroize::Zeroizing;
fn denied() -> syscall::SysError {
    syscall::SysError::from(syscall::NativeError::AccessDenied.into_raw())
}
pub(crate) fn authenticate_broker(endpoint: u32) -> syscall::SysResult<()> {
    if endpoint == 0
        || capability::check_thread(u64::from(endpoint), "capabilities.manage") != Ok(1)
    {
        return Err(denied());
    }
    Ok(())
}
pub fn perform(operation: &[u8]) -> syscall::SysResult<()> {
    let endpoint =
        u32::try_from(crate::process::find_by_name("capability.service")?).map_err(|_| denied())?;
    authenticate_broker(endpoint)?;
    let mut request = Zeroizing::new(
        [0; capability::administrator::HEADER + capability::administrator::MAX_OPERATION],
    );
    let length = capability::administrator::encode_operation(operation, &mut request[..])
        .map_err(|_| syscall::SysError::from(syscall::NativeError::InvalidArgument.into_raw()))?;
    let mut objects = ipc::IpcObjectHandles::default();
    let mut reply = [0; 8];
    let result = ipc::call_object_handles(endpoint, &request[..length], &mut reply, &mut objects);
    let unexpected = objects.count != 0 || objects.delivery_flags != 0;
    for entry in objects
        .handles
        .iter()
        .take((objects.count as usize).min(objects.handles.len()))
    {
        if entry.handle != 0 {
            let _ = crate::handle::close(entry.handle);
        }
    }
    let message = result?;
    authenticate_broker(endpoint)?;
    if unexpected || message >> 32 != u64::from(endpoint) || message as u32 != 8 {
        return Err(denied());
    }
    match u64::from_le_bytes(reply) {
        0 => Ok(()),
        status @ 1..=4095 => Err(syscall::SysError::from_raw(-(status as i64))),
        _ => Err(denied()),
    }
}
