//! Unnamed POSIX semaphores over native address waits, with no service RPC.

use super::*;
use mochios_posix_client::semaphore::{Error, Semaphore};
use mochios_posix_client::synchronization::{self, WaitStatus};

const ETIMEDOUT: c_int = 116;

fn error(error: Error) -> c_int {
    match error {
        Error::Invalid => EINVAL,
        Error::Overflow => EOVERFLOW,
    }
}

fn result(result: Result<(), c_int>) -> c_int {
    match result {
        Ok(()) => 0,
        Err(error) => {
            set_errno(error);
            -1
        }
    }
}

unsafe fn semaphore<'a>(pointer: *mut Semaphore) -> Result<&'a Semaphore, c_int> {
    if pointer.is_null() || pointer as usize % core::mem::align_of::<Semaphore>() != 0 {
        return Err(EINVAL);
    }
    Ok(unsafe { &*pointer })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_init(pointer: *mut Semaphore, shared: c_int, value: u32) -> c_int {
    if pointer.is_null() || pointer as usize % core::mem::align_of::<Semaphore>() != 0 {
        return result(Err(EINVAL));
    }
    match Semaphore::new(value, shared != 0) {
        Ok(semaphore) => {
            unsafe { pointer.write(semaphore) };
            0
        }
        Err(err) => result(Err(error(err))),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_destroy(pointer: *mut Semaphore) -> c_int {
    result(unsafe { semaphore(pointer) }.and_then(|semaphore| semaphore.destroy().map_err(error)))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_getvalue(pointer: *mut Semaphore, value: *mut c_int) -> c_int {
    result((|| {
        if value.is_null() || value as usize % core::mem::align_of::<c_int>() != 0 {
            return Err(EINVAL);
        }
        let count = unsafe { semaphore(pointer) }?.value().map_err(error)?;
        unsafe { value.write(count as c_int) };
        Ok(())
    })())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_trywait(pointer: *mut Semaphore) -> c_int {
    result((|| {
        if unsafe { semaphore(pointer) }?.try_take().map_err(error)? {
            Ok(())
        } else {
            Err(EAGAIN)
        }
    })())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_post(pointer: *mut Semaphore) -> c_int {
    result((|| {
        let semaphore = unsafe { semaphore(pointer) }?;
        semaphore.post().map_err(error)?;
        // Broadcast: a canceled/interrupted selected waiter must not strand
        // a posted token while other waiters remain asleep. No TLS or RPC.
        // A valid object's mapping remains alive through the native wake.
        synchronization::wake_u64(semaphore.word(), usize::MAX)
            .map_err(|err| map_kernel_errno(err.raw()))?;
        Ok(())
    })())
}

unsafe fn wait(pointer: *mut Semaphore, timeout: Option<(u64, *const Timespec)>) -> c_int {
    pthread_testcancel();
    if let Some((clock, _)) = timeout {
        if !matches!(clock, 1 | 4) {
            return result(Err(EINVAL));
        }
    }
    let semaphore = match unsafe { semaphore(pointer) } {
        Ok(value) => value,
        Err(error) => return result(Err(error)),
    };
    let Some((_, control)) = register_current_thread() else {
        return result(Err(EAGAIN));
    };
    let caught = control.nonrestart_signal_generation.load(Ordering::Acquire);
    // Incidental cancellation points inside a signal handler must not exit
    // while token admission is in progress. Re-enable after releasing owners.
    let previous = control
        .cancel_state
        .swap(PTHREAD_CANCEL_DISABLE, Ordering::AcqRel);
    let pending =
        || previous == PTHREAD_CANCEL_ENABLE && control.cancel_pending.load(Ordering::Acquire) != 0;
    let mut absolute = None;
    let outcome = (|| {
        loop {
            // Guard snapshot precedes the checks, closing notification-to-wait
            // races for both cancellation and caught signals.
            let notification = control.multiplex_generation.load(Ordering::Acquire);
            if pending() || control.nonrestart_signal_generation.load(Ordering::Acquire) != caught {
                return Err(EINTR);
            }
            if semaphore.try_take().map_err(error)? {
                // This CAS commits the token: no cancellation check between
                // acquisition and returning success (no lossy rollback).
                return Ok(());
            }
            let limit = if let Some((clock, time)) = timeout {
                let absolute = match absolute {
                    Some(value) => value,
                    None => {
                        if time.is_null() || time as usize % core::mem::align_of::<Timespec>() != 0
                        {
                            return Err(EINVAL);
                        }
                        let time = unsafe { &*time };
                        if !(0..1_000_000_000).contains(&time.tv_nsec) {
                            return Err(EINVAL);
                        }
                        let value = (i128::from(time.tv_sec) * 1_000_000_000
                            + i128::from(time.tv_nsec))
                        .max(0);
                        let value = u64::try_from(value).map_err(|_| EOVERFLOW)?;
                        absolute = Some(value);
                        value
                    }
                };
                let limit = super::pthread_time::deadline(clock as c_int, absolute)?;
                if monotonic_nanoseconds()? >= limit {
                    return Err(ETIMEDOUT);
                }
                limit
            } else {
                syscall::ADDRESS_WAIT_INFINITE
            };
            match synchronization::wait_u64_guarded(
                semaphore.word(),
                0,
                &control.multiplex_generation,
                notification,
                limit,
            ) {
                Ok(WaitStatus::DeadlineReached) => return Err(ETIMEDOUT),
                Ok(_) => {}
                Err(err) if map_kernel_errno(err.raw()) == EINTR => {}
                Err(err) => return Err(map_kernel_errno(err.raw())),
            }
        }
    })();
    // Failure has acquired no token, so cancellation can still take precedence.
    let canceled = outcome.is_err() && pending();
    control.cancel_state.store(previous, Ordering::Release);
    if canceled {
        finish_thread(control, usize::MAX as *mut c_void);
    }
    result(outcome)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_wait(pointer: *mut Semaphore) -> c_int {
    unsafe { wait(pointer, None) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_timedwait(pointer: *mut Semaphore, time: *const Timespec) -> c_int {
    unsafe { wait(pointer, Some((1, time))) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_clockwait(
    pointer: *mut Semaphore,
    clock: u64,
    time: *const Timespec,
) -> c_int {
    unsafe { wait(pointer, Some((clock, time))) }
}
