//! Publish an already consumed service event without dereferencing C storage.
use super::*;

pub(super) fn publish(process_id: u64, status: u32, output: *mut c_int) -> Result<c_int, c_int> {
    if process_id == 0 {
        return Ok(0);
    }
    let process_id = c_int::try_from(process_id).map_err(|_| EOVERFLOW)?;
    if !output.is_null() {
        user_copy::write(output.cast(), &status.to_ne_bytes())?;
    }
    // A copy failure does not recreate an event already consumed by the service.
    Ok(process_id)
}
