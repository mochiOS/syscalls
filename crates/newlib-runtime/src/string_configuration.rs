//! POSIX string configuration is userspace policy, not kernel information.
use super::*;
use mochios_posix_client::configuration::{CS_PATH, DEFAULT_EXECUTABLE_PATH};

#[unsafe(no_mangle)]
pub extern "C" fn confstr(name: c_int, buffer: *mut c_char, length: usize) -> usize {
    if name != CS_PATH {
        set_errno(EINVAL);
        return 0;
    }
    // A zero-length query must ignore the buffer, even when it is invalid.
    // Include the terminator in the required size, including after truncation.
    let required = DEFAULT_EXECUTABLE_PATH.len() + 1;
    if length != 0 {
        let _delivery = defer_native_delivery();
        let copied = DEFAULT_EXECUTABLE_PATH.len().min(length - 1);
        if let Err(error) =
            user_copy::write_c_string(buffer.cast(), &DEFAULT_EXECUTABLE_PATH[..copied])
        {
            set_errno(error);
            return 0;
        }
    }
    required
}
