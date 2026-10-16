//! Receive cwd into runtime-owned memory before touching the application's
//! output. No application mutable slice may span a reentrant IPC callback.
use super::*;

pub(super) fn copy(buffer: *mut c_char, size: usize) -> Result<*mut c_char, c_int> {
    if buffer.is_null() || size == 0 {
        return Err(EINVAL);
    }
    let client = posix_client().map_err(map_posix_client_error)?;
    let mut path = [0; posix_protocol::MAX_PATH_LEN];
    let length = client.getcwd(&mut path).map_err(map_posix_client_error)?;
    let path = path.get(..length).ok_or(EIO)?;
    if path.first() != Some(&b'/') || path.contains(&0) {
        return Err(EIO);
    }
    let needed = length.checked_add(1).ok_or(EIO)?;
    if needed > size {
        return Err(ERANGE);
    }
    if (buffer as usize).checked_add(needed).is_none() {
        return Err(EFAULT);
    }
    // Only bounded response bytes are copied, not a slice formed from an
    // untrusted size_t. All fallible service/shape/size checks precede writes.
    user_copy::write_c_string(buffer.cast(), path)?;
    Ok(buffer)
}
