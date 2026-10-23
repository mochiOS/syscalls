//! Read-only terminal observations through retained native Handle authority.
use super::*;

pub(super) fn observe(
    entry: FdEntry,
    query: u64,
    control: u64,
    output: &mut [u8],
) -> Result<usize, c_int> {
    if !matches!(
        entry.handle.kind,
        FdKind::ObjectPty | FdKind::ObjectSpecial | FdKind::ObjectTerminalFile
    ) {
        return Err(ENOTTY);
    }
    let (operation, code) = if entry.rights & syscall::HANDLE_RIGHT_READ != 0 {
        (syscall::SyscallNumber::HandleQuery, query)
    } else {
        (syscall::SyscallNumber::HandleControl, control)
    };
    let count = syscall_errno(syscall::raw_syscall6(
        operation,
        entry.handle.lower_handle,
        code,
        0,
        0,
        output.as_mut_ptr() as u64,
        output.len() as u64,
    ))
    .map_err(|error| match error {
        ENOTSUP | ENOSYS if entry.handle.kind == FdKind::ObjectSpecial => ENOTTY,
        error => error,
    })?;
    usize::try_from(count).map_err(|_| EOVERFLOW)
}
