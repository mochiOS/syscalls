//! Obtain a name from a pinned master object, never from a guessed inode/PID.
use super::*;

pub(super) fn copy(entry: FdEntry, output: *mut c_char, capacity: usize) -> Result<(), c_int> {
    if output.is_null() {
        return Err(EFAULT);
    }
    let mut bytes = [0; posix_protocol::pty_name::MAX_LEN];
    let length = terminal_control(
        entry,
        posix_protocol::PTY_CONTROL_GET_SLAVE_NAME,
        &[],
        &mut bytes,
    )?;
    let name = bytes.get(..length).ok_or(EIO)?;
    posix_protocol::pty_name::decode(name).map_err(|_| EIO)?;
    if capacity < length {
        return Err(ERANGE);
    }
    user_copy::write(output.cast(), name)
}

pub(super) fn get(fd: c_int, output: *mut c_char, capacity: usize) -> Result<c_int, c_int> {
    io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            copy(**entry, output, capacity)?;
            Ok(0)
        },
    )
}
