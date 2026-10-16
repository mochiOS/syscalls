//! A directory refill keeps its source reference through I/O and state updates.
use super::*;

pub(super) fn refill(stream: &mut DirStream) -> Result<bool, c_int> {
    io_resources::with(
        || with_fd_entry(stream.fd),
        |entry| {
            if entry.handle.kind != FdKind::ObjectDirectory {
                return Err(EBADF);
            }
            let read = syscall_errno(syscall::raw_syscall3(
                syscall::SyscallNumber::HandleRead,
                entry.handle.lower_handle,
                stream.buffer.as_mut_ptr() as u64,
                stream.buffer.len() as u64,
            ))?;
            let count = usize::try_from(read).map_err(|_| EIO)?;
            if count > stream.buffer.len() {
                return Err(EIO);
            }
            stream.buffer_offset = 0;
            stream.buffer_len = count;
            Ok(count != 0)
        },
    )
}
