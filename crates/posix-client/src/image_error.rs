//! Operation-specific error translation for native image admission.
use crate::newlib_errno;

/// Image contents rejected by the native loader are an exec-format failure.
/// Do not give ordinary bad arguments, denied authority, I/O or VM failures
/// this meaning: execvp may choose an interpreter only for ENOEXEC.
pub const fn errno(status: i64) -> i32 {
    if matches!(
        mnu_abi::status::Error::from_raw(status as u64),
        Some(mnu_abi::status::Error::InvalidFormat)
    ) {
        newlib_errno::ENOEXEC
    } else {
        newlib_errno::from_status(status)
    }
}
