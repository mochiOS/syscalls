use crate::syscall::{EINVAL, SysError};

/// Workspace failures carry negative statuses. Positive values are protocol
/// results (such as panel cancellation), never native error encodings.
pub(super) fn status_error(status: i32) -> SysError {
    SysError::from_raw(if status < 0 {
        i64::from(status)
    } else {
        EINVAL as i64
    })
}
