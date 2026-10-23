//! CPU-clock sleeps own a private completion reference, never a public FD.
//! Callback cleanup and child fork discard share the ordinary FD pin book.
use super::*;
use posix_protocol::cpu_sleep as wire;

pub(super) fn target(clock: u64) -> Option<u64> {
    if clock == 2 {
        Some(0)
    } else {
        mochios_posix_client::process_clock::target(clock)
    }
}

struct Pending {
    completion: fd_lease::Lease,
    deadline: u128,
    packet: [u8; wire::COMPLETION_LEN],
    received: usize,
}

fn clock_error(error: c_int) -> c_int {
    if error == ESRCH { EINVAL } else { error }
}

pub(super) fn sleep(
    process: u64,
    flags: c_int,
    request: Timespec,
    remaining: *mut Timespec,
) -> Result<(), c_int> {
    let absolute = flags == mochios_posix_client::time::TIMER_ABSTIME;
    if flags != 0 && !absolute
        || request.tv_sec < 0
        || !(0..1_000_000_000).contains(&request.tv_nsec)
    {
        return Err(EINVAL);
    }
    let nanoseconds = request.tv_sec as u128 * 1_000_000_000 + request.tv_nsec as u128;
    let owner = native_process_id().map_err(|error| map_kernel_errno(error.raw()))?;
    let subject = if process == 0 { owner } else { process };
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let caught = control.caught_signal_generation.load(Ordering::Acquire);
    // SAFETY: after preparation, Pending owns only a lifetime pin and private
    // bytes. Native waits/reads acquire no new references. Foreign fork pins
    // are discarded through BORROWS without touching vanished thread stacks.
    let (result, deadline) = unsafe {
        io_resources::with_fork_opaque(
            || {
                let pending = posix_client()
                    .map_err(map_posix_client_error)?
                    .begin_process_cpu_sleep(wire::Request {
                        process,
                        absolute,
                        nanoseconds,
                    })
                    .map_err(map_posix_client_error)
                    .map_err(clock_error)?;
                let entry = object_entry(
                    u64::from(pending.completion.handle),
                    pending.completion.rights,
                    FdKind::ObjectStreamRead,
                    O_NONBLOCK,
                );
                Ok(Pending {
                    completion: fd_lease::Lease::adopt_private(entry)?,
                    deadline: pending.deadline_ns,
                    packet: [0; wire::COMPLETION_LEN],
                    received: 0,
                })
            },
            |_| true,
            |pending| Ok((wait(pending, control, caught, owner), pending.deadline)),
        )
    }?;
    // Resources are gone before cancellation cleanup or checked copyout.
    pthread_testcancel();
    if result == Err(EINTR) && !absolute && !remaining.is_null() {
        let left =
            deadline.saturating_sub(process_clock::nanoseconds(subject).map_err(clock_error)?);
        let seconds = i64::try_from(left / 1_000_000_000).map_err(|_| EOVERFLOW)?;
        time_memory::write_timespec(
            remaining,
            Timespec {
                tv_sec: seconds,
                tv_nsec: (left % 1_000_000_000) as i64,
            },
        )?;
    }
    result
}

fn wait(
    pending: &mut Pending,
    control: &ThreadControl,
    caught: u64,
    owner: u64,
) -> Result<(), c_int> {
    loop {
        if io_cancellation_requested(control)
            || control.caught_signal_generation.load(Ordering::Acquire) != caught
            || native_process_id().map_err(|error| map_kernel_errno(error.raw()))? != owner
        {
            return Err(EINTR);
        }
        let available = pending.packet.len() - pending.received;
        let result = {
            // This read is nonblocking. Keep its label check and dispatch in
            // one delivery-deferred section so a handler cannot fork and
            // replace that label between them. Reopen callbacks before waiting.
            let _native = defer_native_delivery();
            if !pending.completion.is_current() {
                return Err(EINTR);
            }
            let remaining = &mut pending.packet[pending.received..];
            syscall_errno(syscall::raw_syscall4(
                syscall::SyscallNumber::StreamRead,
                pending.completion.handle.lower_handle,
                remaining.as_mut_ptr() as u64,
                remaining.len() as u64,
                mnu_abi::STREAM_IO_TRY,
            ))
        };
        // A signal handler can fork during the initial nonblocking read too.
        // Its copied result does not describe a completion owned by the child.
        if !pending.completion.is_current() {
            return Err(EINTR);
        }
        match result {
            Ok(count) if count != 0 && count <= available as u64 => {
                pending.received += count as usize;
                if pending.received == pending.packet.len() {
                    return wire::decode_completion(&pending.packet)
                        .map_err(|_| EIO)?
                        .map_err(|status| {
                            clock_error(map_posix_client_error(PosixClientError::Remote(status)))
                        });
                }
            }
            Ok(_) => return Err(EIO), // EOF/invalid count is never completion.
            Err(EAGAIN) => {
                let mut item = [syscall::HandleWaitItem {
                    handle: pending.completion.handle.lower_handle as u32,
                    interests: syscall::HANDLE_SIGNAL_READABLE | syscall::HANDLE_SIGNAL_PEER_CLOSED,
                    ..Default::default()
                }];
                wait_for_multiplex_while(
                    &mut item,
                    syscall::HANDLE_WAIT_INFINITE,
                    control,
                    caught,
                    || pending.completion.is_current(),
                )?;
            }
            Err(error) => return Err(error),
        }
    }
}
