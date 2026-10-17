use crate::syscall::{NativeError, SysError, SysResult};

// A successful Handle-producing call must return a nonzero process-local
// selector. Do not truncate malformed results or invent a POSIX errno.
pub(crate) fn decode(raw: u64) -> SysResult<u32> {
    u32::try_from(raw)
        .ok()
        .filter(|handle| *handle != 0)
        .ok_or(SysError::from_raw(
            NativeError::BackingFailure.into_raw() as i64
        ))
}

// The returned byte count describes this transfer, not a required buffer size.
// A malformed success is a native backing failure, not POSIX overflow policy.
pub(crate) fn transfer_length(raw: u64, capacity: usize) -> SysResult<usize> {
    usize::try_from(raw)
        .ok()
        .filter(|length| *length <= capacity)
        .ok_or(SysError::from_raw(
            NativeError::BackingFailure.into_raw() as i64
        ))
}
