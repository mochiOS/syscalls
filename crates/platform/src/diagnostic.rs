//! Authorized reads of native diagnostic history. This does not open a file
//! or select a persistence policy; the caller owns its cursor and storage.

use crate::syscall::{self, SysError, SysResult};
use mnu_abi::diagnostic::{READ_MAX_BYTES, RESULT_LEN, ReadResult};

pub fn read(cursor: u64, output: &mut [u8]) -> SysResult<(usize, ReadResult)> {
    if output.len() > READ_MAX_BYTES {
        return Err(SysError::from_raw(syscall::EINVAL as i64));
    }
    let mut metadata = [0; RESULT_LEN];
    let copied = syscall::call4(
        syscall::SyscallNumber::DiagnosticRead,
        cursor,
        output.as_mut_ptr() as u64,
        output.len() as u64,
        metadata.as_mut_ptr() as u64,
    )?;
    let result =
        ReadResult::from_bytes(&metadata).ok_or(SysError::from_raw(syscall::EIO as i64))?;
    if copied > output.len() as u64
        || cursor
            .checked_add(result.dropped)
            .and_then(|start| start.checked_add(copied))
            != Some(result.next_cursor)
    {
        return Err(SysError::from_raw(syscall::EIO as i64));
    }
    Ok((copied as usize, result))
}
