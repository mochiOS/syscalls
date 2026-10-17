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
