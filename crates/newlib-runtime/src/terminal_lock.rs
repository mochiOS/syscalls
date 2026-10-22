//! Master authority is pinned through the local FD lease, never recovered
//! from a numeric terminal ID or a pathname.
use super::*;

pub(super) fn unlock(fd: c_int) -> Result<c_int, c_int> {
    io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            if entry.rights & syscall::HANDLE_RIGHT_WRITE == 0 {
                return Err(EBADF);
            }
            let length = terminal_control(
                **entry,
                posix_protocol::PTY_CONTROL_SET_SLAVE_LOCK,
                &0u32.to_le_bytes(),
                &mut [],
            )
            .map_err(|error| if error == ENOTTY { EINVAL } else { error })?;
            if length != 0 {
                return Err(EIO);
            }
            Ok(0)
        },
    )
}
