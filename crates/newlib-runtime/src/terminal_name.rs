//! Obtain a name from a pinned master object, never from a guessed inode/PID.
use super::*;

/// Fixed storage owned by one runtime thread slot. No Rust references to its
/// contents survive native calls, which may deliver a reentrant C handler.
pub(super) struct Buffer(core::cell::UnsafeCell<[u8; posix_protocol::pty_name::MAX_LEN]>);

// SAFETY: The runtime accesses this storage only through the current thread's
// registered control, or while exclusively claiming a free thread slot. Other
// threads must not read/write it. Returned C pointers follow ptsname lifetime
// rules; their use after the owner exits or reuses the buffer is not protected.
unsafe impl Sync for Buffer {}

impl Buffer {
    pub(super) const fn new() -> Self {
        Self(core::cell::UnsafeCell::new(
            [0; posix_protocol::pty_name::MAX_LEN],
        ))
    }

    /// # Safety
    /// The caller must exclusively own this slot before publishing its thread.
    pub(super) unsafe fn reset(&self) {
        unsafe { self.0.get().write([0; posix_protocol::pty_name::MAX_LEN]) };
    }
}

/// # Safety
/// `buffer` must belong to the calling thread and stay at its current address
/// for as long as the returned C pointer is used. No other thread may access it.
pub(super) unsafe fn owned(fd: c_int, buffer: &Buffer) -> Result<*mut c_char, c_int> {
    // Derive a raw pointer without ever constructing an aliased &mut buffer.
    let output = buffer.0.get().cast::<c_char>();
    get(fd, output, posix_protocol::pty_name::MAX_LEN)?;
    Ok(output)
}

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
