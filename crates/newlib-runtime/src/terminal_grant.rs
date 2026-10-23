//! Transfer only the leased master controller; no user pathname or UID input.
use super::*;

pub(super) fn grant(fd: c_int) -> Result<c_int, c_int> {
    io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            if entry.rights & syscall::HANDLE_RIGHT_WRITE == 0 {
                return Err(EBADF);
            }
            if entry.handle.kind != FdKind::ObjectPty {
                return Err(EINVAL);
            }
            let rights = syscall::HANDLE_RIGHT_WRITE
                | syscall::HANDLE_RIGHT_CONTROL
                | syscall::HANDLE_RIGHT_TRANSFER;
            if entry.rights & rights != rights {
                return Err(EACCES);
            }
            let master = ObjectHandleAttachment {
                handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                rights,
            };
            posix_client()
                .map_err(map_posix_client_error)?
                .grant_pty_master(master)
                .map_err(map_posix_client_error)?;
            Ok(0)
        },
    )
}
