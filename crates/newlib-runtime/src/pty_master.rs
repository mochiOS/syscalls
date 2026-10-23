//! Reserve one local FD and own its native master until publication commits.
use super::fd_creation::{PendingFdReservation, PendingHandles};
use super::*;

pub(super) fn create(flags: c_int) -> Result<c_int, c_int> {
    const O_NOCTTY: c_int = 0x8000; // newlib sys/_default_fcntl.h
    if flags & 3 != 2 || flags & !(3 | O_NOCTTY | O_NONBLOCK | O_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    io_resources::with(
        || {
            let limit = process_fd_limit()?;
            let pending =
                PendingFdReservation(state().fds.reserve_from(0, limit).map_err(|_| EMFILE)?);
            let master = posix_client()
                .and_then(|client| client.open_pty_master())
                .map_err(map_posix_client_error)?;
            let opened = PendingHandles {
                handles: [master],
                installed: false,
            };
            let required = syscall::HANDLE_RIGHT_READ
                | syscall::HANDLE_RIGHT_WRITE
                | syscall::HANDLE_RIGHT_WAIT
                | syscall::HANDLE_RIGHT_CONTROL
                | syscall::HANDLE_RIGHT_DUPLICATE
                | syscall::HANDLE_RIGHT_TRANSFER;
            if master.rights & required != required {
                return Err(EACCES);
            }
            if flags & O_NONBLOCK != 0 {
                syscall_errno(syscall::raw_syscall2(
                    syscall::SyscallNumber::HandleOptionsSet,
                    u64::from(master.handle),
                    syscall::HANDLE_OPTION_NONBLOCKING,
                ))?;
            }
            Ok((pending, opened))
        },
        |(pending, opened)| {
            let _native = defer_native_delivery();
            let master = opened.handles[0];
            let entry = object_entry(
                u64::from(master.handle),
                master.rights,
                FdKind::ObjectPty,
                flags,
            );
            let fd = state()
                .fds
                .commit_reservation(&pending.0, entry)
                .map_err(|_| EIO)?;
            opened.installed = true;
            Ok(fd)
        },
    )
}
