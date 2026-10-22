//! Snapshot provider read policy with READ authority, then use native data I/O
//! and cancellable waits. No borrowed caller buffer survives as a Rust slice.
use super::*;

pub(super) fn read(entry: FdEntry, buffer: *mut c_void, length: usize) -> Result<isize, c_int> {
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let caught = control.nonrestart_signal_generation.load(Ordering::Acquire);
    let nonblocking = handle_is_nonblocking(entry)?;
    let mut bytes = [0; posix_protocol::TERMINAL_READ_SETTINGS_LEN];
    let returned = syscall_errno(syscall::raw_syscall6(
        syscall::SyscallNumber::HandleQuery,
        entry.handle.lower_handle,
        posix_protocol::PTY_QUERY_READ_SETTINGS,
        0,
        0,
        bytes.as_mut_ptr() as u64,
        bytes.len() as u64,
    ))?;
    if returned != bytes.len() as u64 {
        return Err(EIO);
    }
    let settings = posix_protocol::decode_terminal_read_settings(&bytes).map_err(|_| EIO)?;
    mochios_posix_client::terminal_read::read(
        settings,
        length,
        nonblocking,
        EAGAIN,
        |offset, remaining| {
            let address = (buffer as usize).checked_add(offset).ok_or(EFAULT)?;
            match retry_terminal_operation(posix_protocol::SIGNAL_TTIN, || {
                syscall_errno(syscall::raw_syscall3(
                    syscall::SyscallNumber::HandleRead,
                    entry.handle.lower_handle,
                    address as u64,
                    remaining as u64,
                ))
            }) {
                Ok(count) => usize::try_from(count)
                    .map(mochios_posix_client::terminal_read::Attempt::Bytes)
                    .map_err(|_| EIO),
                Err(EAGAIN) => Ok(mochios_posix_client::terminal_read::Attempt::Unavailable),
                Err(error) => Err(error),
            }
        },
        monotonic_nanoseconds,
        |deadline| match wait_for_handle_capacity(
            entry,
            syscall::HANDLE_SIGNAL_READABLE | syscall::HANDLE_SIGNAL_PEER_CLOSED,
            control,
            caught,
            0,
            deadline.unwrap_or(syscall::HANDLE_WAIT_INFINITE),
        ) {
            Ok(_) => Ok(true),
            Err(EAGAIN) if deadline.is_some() => Ok(false),
            Err(error) => Err(error),
        },
    )
    .map(|count| count as isize)
    .map_err(|error| match error {
        mochios_posix_client::terminal_read::Error::InvalidResult => EIO,
        mochios_posix_client::terminal_read::Error::Io(error) => error,
    })
}
