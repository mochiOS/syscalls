//! Named FIFO data goes directly through its native Provider Handle. Only a
//! would-block result creates a one-shot notification through posix.service.
use super::*;
use posix_protocol::fifo::WaitCondition;

fn attempt(entry: FdEntry, buffer: u64, length: usize, writing: bool) -> Result<usize, c_int> {
    let result = syscall::raw_syscall3(
        if writing {
            syscall::SyscallNumber::HandleWrite
        } else {
            syscall::SyscallNumber::HandleRead
        },
        entry.handle.lower_handle,
        buffer,
        length as u64,
    );
    // An owner dying is a backing failure, not logical FIFO EOF/SIGPIPE.
    if result.raw() == mnu_abi::status::Error::PeerClosed.into_raw() {
        return Err(EIO);
    }
    let count = usize::try_from(syscall_errno(result)?).map_err(|_| EIO)?;
    if count > length {
        return Err(EIO);
    }
    Ok(count)
}

fn interrupted(control: &ThreadControl, caught: u64) -> bool {
    io_cancellation_requested(control)
        || control.nonrestart_signal_generation.load(Ordering::Acquire) != caught
}

fn wait(
    entry: FdEntry,
    condition: WaitCondition,
    control: &ThreadControl,
    caught: u64,
) -> Result<(), c_int> {
    // After preparation this owns a BORROWS private lifetime pin. Fork startup
    // discards foreign pins; an inherited caller guard is rejected by epoch.
    // Native waits below acquire no additional references, as for cpu_sleep.
    unsafe {
        io_resources::with_fork_opaque(
            || {
                let job = posix_client()
                    .map_err(map_posix_client_error)?
                    .fifo_wait(
                        ObjectHandleAttachment {
                            handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                            rights: entry.rights,
                        },
                        condition,
                    )
                    .map_err(map_posix_client_error)?;
                fd_lease::Lease::adopt_private(object_entry(
                    u64::from(job.handle),
                    job.rights,
                    FdKind::ObjectFifo,
                    O_NONBLOCK,
                ))
            },
            |_| true,
            |completion| {
                let mut item = syscall::HandleWaitItem {
                    handle: u32::try_from(completion.handle.lower_handle).map_err(|_| EBADF)?,
                    interests: syscall::HANDLE_SIGNAL_READABLE | syscall::HANDLE_SIGNAL_PEER_CLOSED,
                    ..Default::default()
                };
                mochios_posix_client::multiplex::wait_cancellable(
                    caught,
                    || control.nonrestart_signal_generation.load(Ordering::Acquire),
                    || io_cancellation_requested(control) || !completion.is_current(),
                    || control.multiplex_generation.load(Ordering::Acquire),
                    |generation| {
                        let guard = mnu_abi::HandleWaitGuard {
                            address: (&control.multiplex_generation as *const AtomicU64) as u64,
                            expected: generation,
                        };
                        match syscall_errno(syscall::raw_syscall4(
                            syscall::SyscallNumber::HandleWaitManyGuarded,
                            (&mut item as *mut syscall::HandleWaitItem) as u64,
                            1,
                            syscall::HANDLE_WAIT_INFINITE,
                            (&guard as *const mnu_abi::HandleWaitGuard) as u64,
                        )) {
                            Ok(_) => Ok(true),
                            Err(EAGAIN) => Ok(false),
                            Err(error) => Err(error),
                        }
                    },
                    || Ok(false),
                )
                .map_err(|error| match error {
                    mochios_posix_client::multiplex::WaitError::Cancelled
                    | mochios_posix_client::multiplex::WaitError::Interrupted => EINTR,
                    mochios_posix_client::multiplex::WaitError::Io(error) => error,
                })?;
                if !completion.is_current() {
                    return Err(EINTR);
                }
                if item.observed & syscall::HANDLE_SIGNAL_READABLE == 0 {
                    return Err(EIO);
                }
                Ok(())
            },
        )
    }
}

pub(super) fn read(entry: FdEntry, buffer: *mut c_void, length: usize) -> Result<isize, c_int> {
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let caught = control.nonrestart_signal_generation.load(Ordering::Acquire);
    loop {
        if interrupted(control, caught) {
            return Err(EINTR);
        }
        match attempt(entry, buffer as u64, length, false) {
            Err(EAGAIN) if !handle_is_nonblocking(entry)? => {
                wait(entry, WaitCondition::Read, control, caught)?
            }
            result => return result.map(|count| count as isize),
        }
    }
}

fn prefix(written: usize, error: c_int) -> Result<isize, c_int> {
    if written != 0 {
        Ok(written as isize)
    } else {
        Err(error)
    }
}

pub(super) fn write(entry: FdEntry, buffer: *const c_void, length: usize) -> Result<isize, c_int> {
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let caught = control.nonrestart_signal_generation.load(Ordering::Acquire);
    let mut written = 0;
    loop {
        if interrupted(control, caught) {
            return prefix(written, EINTR);
        }
        let remaining = length - written;
        let Some(address) = (buffer as u64).checked_add(written as u64) else {
            return prefix(written, EFAULT);
        };
        match attempt(entry, address, remaining, true) {
            Ok(count) => {
                if length <= posix_protocol::PIPE_BUF && count != remaining {
                    return prefix(written, EIO);
                }
                written += count;
                if count == 0 || written == length {
                    return Ok(written as isize);
                }
                match handle_is_nonblocking(entry) {
                    Ok(true) => return Ok(written as isize),
                    Ok(false) => (),
                    Err(error) => return prefix(written, error),
                }
            }
            Err(EAGAIN) => {
                match handle_is_nonblocking(entry) {
                    Ok(true) => return prefix(written, EAGAIN),
                    Err(error) => return prefix(written, error),
                    Ok(false) => (),
                }
                if let Err(error) = wait(entry, WaitCondition::Write(remaining), control, caught) {
                    return prefix(written, error);
                }
            }
            Err(EPIPE) => {
                if let Err(error) = io_resources::with(
                    || Ok(()),
                    |_| generate_thread_signal(posix_protocol::SIGNAL_PIPE),
                ) {
                    return prefix(written, error);
                }
                return prefix(written, EPIPE);
            }
            Err(error) => return prefix(written, error),
        }
    }
}
