//! A directory refill keeps its source reference through I/O and state updates.
use super::*;

struct PendingDirectory {
    allocation: *mut DirStream,
    published: bool,
    // Acquired only at the final, non-waiting handoff. Keep delivery closed
    // until the enclosing allocation scope has retired, not merely until open
    // returns its descriptor to this Rust frame.
    completion: Option<mochios_posix_client::upcall_guard::Guard<'static>>,
}

impl PendingDirectory {
    fn allocate() -> Result<Self, c_int> {
        let allocation = unsafe { malloc(core::mem::size_of::<DirStream>()) }.cast::<DirStream>();
        if allocation.is_null() {
            return Err(ENOMEM);
        }
        Ok(Self {
            allocation,
            published: false,
            completion: None,
        })
    }
}

impl Drop for PendingDirectory {
    fn drop(&mut self) {
        if !self.published {
            unsafe { free(self.allocation.cast()) };
        }
    }
}

pub(super) fn open(path: *const c_char) -> Result<*mut c_void, c_int> {
    io_resources::with(PendingDirectory::allocate, |pending| {
        // The allocation is tracked before pathname admission can run C.
        const O_DIRECTORY: c_int = 0x200000;
        let flags = O_DIRECTORY | O_CLOEXEC;
        let mut initialize = |fd| {
            pending.completion = defer_native_delivery();
            // The descriptor is not visible yet. A fault here leaves its
            // Handle and reservation in open's inner tracked owner.
            unsafe { pending.allocation.write(DirStream::new(fd)) };
            Ok(())
        };
        match file_mutation::open_with_handoff(path, flags, 0, &mut initialize) {
            Err(error) if error == EACCES || error == EPERM => {
                retry_open_with_prompt_using(path, flags, || {
                    file_mutation::open_with_handoff(path, flags, 0, &mut initialize)
                })?;
            }
            result => {
                result?;
            }
        }
        // The handoff guard still closes delivery after FD installation.
        // No fallible operation may hide that FD before returning its DIR.
        pending.published = true;
        Ok(pending.allocation.cast())
    })
}

pub(super) fn adopt(fd: c_int) -> Result<*mut c_void, c_int> {
    io_resources::with(PendingDirectory::allocate, |pending| {
        pending.completion = defer_native_delivery();
        // Allocate before STATE: the allocator may itself need runtime state.
        // Validate and hand off atomically, without reopening the object or
        // changing its shared directory cursor or descriptor-local flags.
        let state = state();
        let entry = state.fds.get(fd).ok_or(EBADF)?;
        if entry.handle.kind != FdKind::ObjectDirectory {
            return Err(ENOTDIR);
        }
        if !mochios_posix_client::fd::access_allows_read(entry.handle.open_flags as u32)
            || entry.rights & syscall::HANDLE_RIGHT_READ == 0
        {
            return Err(EBADF);
        }
        unsafe { pending.allocation.write(DirStream::new(fd)) };
        pending.published = true;
        Ok(pending.allocation.cast())
    })
}

pub(super) fn rewind(stream: &mut DirStream) -> Result<(), c_int> {
    io_resources::with(
        || with_fd_entry(stream.fd),
        |entry| {
            if entry.handle.kind != FdKind::ObjectDirectory {
                return Err(EBADF);
            }
            syscall_errno(syscall::raw_syscall3(
                syscall::SyscallNumber::HandleSeek,
                entry.handle.lower_handle,
                0,
                syscall::HANDLE_SEEK_START,
            ))?;
            let _native = defer_native_delivery();
            stream.buffer_offset = 0;
            stream.buffer_len = 0;
            Ok(())
        },
    )
}

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

/// Retire the DIR allocation and its FD as one non-callback boundary. No
/// application handler may abandon the frame after free but before close.
pub(super) unsafe fn close(allocation: *mut DirStream) -> c_int {
    let _native = defer_native_delivery();
    let fd = unsafe { (*allocation).fd };
    unsafe { free(allocation.cast()) };
    _close(fd)
}
