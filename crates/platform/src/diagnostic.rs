//! Authorized reads of native diagnostic history. This does not open a file
//! or select a persistence policy; the caller owns its cursor and storage.

use crate::syscall::{self, SysError, SysResult};
pub use mnu_abi::diagnostic::{EXIT_KIND_EXCEPTION, EXIT_KIND_STATUS, EXIT_RECORD_LEN, ExitRecord};
use mnu_abi::diagnostic::{READ_MAX_BYTES, RESULT_LEN, ReadResult};
use mnu_abi::status::Error;

/// Native abnormal termination records. This stream cannot be written by IPC
/// clients. A nonzero exit status alone does not establish a CPU exception.
pub fn read_exits(cursor: u64, output: &mut [u8]) -> SysResult<(usize, ReadResult)> {
    if output.len() > READ_MAX_BYTES
        || output.len() % EXIT_RECORD_LEN != 0
        || cursor % EXIT_RECORD_LEN as u64 != 0
    {
        return Err(SysError::from_raw(Error::InvalidArgument.into_raw() as i64));
    }
    let mut metadata = [0; RESULT_LEN];
    let copied = syscall::call5(
        syscall::SyscallNumber::DiagnosticStreamRead,
        cursor,
        output.as_mut_ptr() as u64,
        output.len() as u64,
        metadata.as_mut_ptr() as u64,
        mnu_abi::diagnostic::STREAM_PROCESS_EXIT,
    )?;
    let result = ReadResult::from_bytes(&metadata)
        .ok_or(SysError::from_raw(Error::BackingFailure.into_raw() as i64))?;
    if copied > output.len() as u64
        || copied % EXIT_RECORD_LEN as u64 != 0
        || result.dropped % EXIT_RECORD_LEN as u64 != 0
        || cursor
            .checked_add(result.dropped)
            .and_then(|start| start.checked_add(copied))
            != Some(result.next_cursor)
    {
        return Err(SysError::from_raw(Error::BackingFailure.into_raw() as i64));
    }
    Ok((copied as usize, result))
}

pub fn read(cursor: u64, output: &mut [u8]) -> SysResult<(usize, ReadResult)> {
    if output.len() > READ_MAX_BYTES {
        return Err(SysError::from_raw(Error::InvalidArgument.into_raw() as i64));
    }
    let mut metadata = [0; RESULT_LEN];
    let copied = syscall::call4(
        syscall::SyscallNumber::DiagnosticRead,
        cursor,
        output.as_mut_ptr() as u64,
        output.len() as u64,
        metadata.as_mut_ptr() as u64,
    )?;
    let result = ReadResult::from_bytes(&metadata)
        .ok_or(SysError::from_raw(Error::BackingFailure.into_raw() as i64))?;
    if copied > output.len() as u64
        || cursor
            .checked_add(result.dropped)
            .and_then(|start| start.checked_add(copied))
            != Some(result.next_cursor)
    {
        return Err(SysError::from_raw(Error::BackingFailure.into_raw() as i64));
    }
    Ok((copied as usize, result))
}
