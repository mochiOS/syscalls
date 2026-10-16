//! Convert failure payloads into the POSIX service's signed wire namespace.
//!
//! This is not the newlib C errno namespace. Native mechanism errors are
//! translated here; libc performs its separate wire-to-C conversion later.

pub const fn normalize_failure(status: i64) -> i32 {
    let magnitude = status.unsigned_abs();
    if magnitude == 0 || magnitude > i32::MAX as u64 {
        return crate::STATUS_EIO;
    }
    let negative = -(magnitude as i64);
    match mnu_abi::status::Error::from_raw(negative as u64) {
        Some(error) => match error {
            mnu_abi::status::Error::LimitExceeded => -75, // wire EOVERFLOW
            mnu_abi::status::Error::InvalidAddress => -14,
            mnu_abi::status::Error::ResourceUnavailable => -12,
            mnu_abi::status::Error::BackingFailure => crate::STATUS_EIO,
            mnu_abi::status::Error::InvalidArgument => -22,
            mnu_abi::status::Error::AccessDenied => -13,
            mnu_abi::status::Error::NotReady => crate::STATUS_EAGAIN,
            mnu_abi::status::Error::AlreadyExists => -17,
            mnu_abi::status::Error::NotFound => -2,
        },
        None if mnu_abi::status::is_error(negative as u64) => crate::STATUS_EIO,
        None => negative as i32,
    }
}
