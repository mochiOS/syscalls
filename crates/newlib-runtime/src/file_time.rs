//! POSIX file times use the common path snapshot and nonlocal-exit FD scopes.
use super::*;

#[path = "file_time_input.rs"]
mod input;

pub(super) fn at(
    dirfd: c_int,
    path: *const c_char,
    times: *const Timespec,
    flags: c_int,
) -> Result<(), c_int> {
    if flags & !(AT_SYMLINK_NOFOLLOW as c_int) != 0 {
        return Err(EINVAL);
    }
    let flags = if flags != 0 {
        posix_protocol::STAT_NOFOLLOW
    } else {
        0
    };
    let times = input::read(times)?;
    path_io::at(dirfd, path, |base, path| {
        posix_client()
            .map_err(map_posix_client_error)?
            .utimens_at(base, path, times, flags)
            .map_err(map_posix_client_error)
    })
}

pub(super) fn fd(fd: c_int, times: *const Timespec) -> Result<(), c_int> {
    let times = input::read(times)?;
    io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            if !matches!(
                entry.handle.kind,
                FdKind::ObjectFile
                    | FdKind::ObjectSpecial
                    | FdKind::ObjectTerminalFile
                    | FdKind::ObjectFifo
                    | FdKind::ObjectDirectory
            ) {
                // A valid stream/socket/VM descriptor is not an invalid FD, but
                // those providers do not yet expose mutable timestamp metadata.
                return Err(ENOTSUP);
            }
            posix_client()
                .map_err(map_posix_client_error)?
                .futimens(
                    ObjectHandleAttachment {
                        handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                        rights: entry.rights,
                    },
                    times,
                )
                .map_err(map_posix_client_error)
        },
    )
}
