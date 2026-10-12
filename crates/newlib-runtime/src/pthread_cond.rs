//! Public condition waits. Cancellation is acted on only after the original
//! mutex is reacquired and the condition's waiter registration is removed.

use super::*;
use mochios_posix_client::pthread_cond::{Condition, Error};
use mochios_posix_client::pthread_mutex::Mutex;
use super::pthread_time::deadline;

const ETIMEDOUT: c_int = 116;

#[repr(C)]
pub struct Attribute {
    initialized: c_int,
    clock: c_int,
    shared: c_int,
}

fn error(error: Error) -> c_int {
    match error {
        Error::Invalid => EINVAL,
        Error::Busy => EBUSY,
        Error::TooManyWaiters => EAGAIN,
    }
}
unsafe fn attribute<'a>(attr: *const Attribute) -> Result<&'a Attribute, c_int> {
    let attr = unsafe { attr.as_ref() }.ok_or(EINVAL)?;
    if attr.initialized != 1 || !matches!(attr.clock, 1 | 4) || !matches!(attr.shared, 0 | 1) {
        return Err(EINVAL);
    }
    Ok(attr)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_condattr_init(attr: *mut Attribute) -> c_int {
    if attr.is_null() {
        return EINVAL;
    }
    unsafe {
        attr.write(Attribute {
            initialized: 1,
            clock: 1,
            shared: 0,
        })
    };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_condattr_destroy(attr: *mut Attribute) -> c_int {
    if let Err(err) = unsafe { attribute(attr) } {
        return err;
    }
    unsafe { (*attr).initialized = 0 };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_condattr_getclock(
    attr: *const Attribute,
    clock: *mut u64,
) -> c_int {
    let attr = match unsafe { attribute(attr) } {
        Ok(attr) => attr,
        Err(err) => return err,
    };
    if clock.is_null() {
        return EINVAL;
    }
    unsafe { clock.write(attr.clock as u64) };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_condattr_setclock(attr: *mut Attribute, clock: u64) -> c_int {
    if let Err(err) = unsafe { attribute(attr) } {
        return err;
    }
    if !matches!(clock, 1 | 4) {
        return EINVAL;
    }
    unsafe { (*attr).clock = clock as c_int };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_condattr_getpshared(
    attr: *const Attribute,
    shared: *mut c_int,
) -> c_int {
    let attr = match unsafe { attribute(attr) } {
        Ok(attr) => attr,
        Err(err) => return err,
    };
    if shared.is_null() {
        return EINVAL;
    }
    unsafe { shared.write(attr.shared) };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_condattr_setpshared(attr: *mut Attribute, shared: c_int) -> c_int {
    if let Err(err) = unsafe { attribute(attr) } {
        return err;
    }
    if !matches!(shared, 0 | 1) {
        return EINVAL;
    }
    unsafe { (*attr).shared = shared };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_init(cond: *mut Condition, attr: *const Attribute) -> c_int {
    if cond.is_null() {
        return EINVAL;
    }
    let clock = if attr.is_null() {
        1
    } else {
        match unsafe { attribute(attr) } {
            Ok(attr) => attr.clock,
            Err(err) => return err,
        }
    };
    unsafe { cond.write(Condition::new(clock)) };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_destroy(cond: *mut Condition) -> c_int {
    let Some(cond) = (unsafe { cond.as_ref() }) else {
        return EINVAL;
    };
    cond.destroy().map_or_else(error, |()| 0)
}

fn notify(cond: *mut Condition, all: bool) -> c_int {
    let Some(cond) = (unsafe { cond.as_ref() }) else {
        return EINVAL;
    };
    let mut wake_error = 0;
    match cond.notify(all, |address, count| {
        if let Err(err) = mochios_posix_client::synchronization::wake_u64(address, count) {
            wake_error = map_kernel_errno(err.raw());
        }
    }) {
        Ok(()) => wake_error,
        Err(err) => error(err),
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_signal(cond: *mut Condition) -> c_int {
    notify(cond, false)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_broadcast(cond: *mut Condition) -> c_int {
    notify(cond, true)
}

unsafe fn wait(
    cond: *mut Condition,
    mutex: *mut Mutex,
    clock: Option<c_int>,
    time: *const Timespec,
) -> c_int {
    let Some(condition) = (unsafe { cond.as_ref() }) else {
        return EINVAL;
    };
    let Some(mutex_ref) = (unsafe { mutex.as_ref() }) else {
        return EINVAL;
    };
    let default_clock = match condition.clock() {
        Ok(clock) => clock,
        Err(err) => return error(err),
    };
    let clock = clock.unwrap_or(default_clock);
    if !matches!(clock, 1 | 4) {
        return EINVAL;
    }
    let absolute = if time.is_null() {
        None
    } else {
        let time = unsafe { time.read() };
        if !(0..1_000_000_000).contains(&time.tv_nsec) {
            return EINVAL;
        }
        let value = (i128::from(time.tv_sec) * 1_000_000_000 + i128::from(time.tv_nsec)).max(0);
        match u64::try_from(value) {
            Ok(value) => Some(value),
            Err(_) => return EOVERFLOW,
        }
    };
    let thread = match native_thread_id() {
        Ok(thread) => thread,
        Err(err) => return map_kernel_errno(err.raw()),
    };
    if let Err(err) = mutex_ref.check_owner(thread) {
        return match err {
            mochios_posix_client::pthread_mutex::Error::Invalid => EINVAL,
            _ => EPERM,
        };
    }
    let Some((_, control)) = register_current_thread() else {
        return EAGAIN;
    };
    pthread_testcancel(); // The caller still owns its mutex here.
    let before = match condition.begin() {
        Ok(before) => before,
        Err(err) => return error(err),
    };
    // Temporary disabling prevents an incidental cancellation point inside a
    // handler/libc call from exiting with the application mutex released.
    let previous = control
        .cancel_state
        .swap(PTHREAD_CANCEL_DISABLE, Ordering::AcqRel);
    let unlocked = unsafe { super::pthread_mutex::pthread_mutex_unlock(mutex) };
    if unlocked != 0 {
        condition.end(before, false, |_, _| {});
        control.cancel_state.store(previous, Ordering::Release);
        return unlocked;
    }
    let pending =
        || previous == PTHREAD_CANCEL_ENABLE && control.cancel_pending.load(Ordering::Acquire) != 0;
    let result = (|| {
        loop {
            // Snapshot the notification before inspecting cancellation. The
            // kernel admits both predicates under the same address wait lock.
            let notification = control.multiplex_generation.load(Ordering::Acquire);
            if pending() {
                return Ok(());
            }
            if condition.word().load(Ordering::Acquire) != before {
                return Ok(());
            }
            let limit = match absolute {
                Some(time) => deadline(clock, time)?,
                None => syscall::ADDRESS_WAIT_INFINITE,
            };
            if limit != syscall::ADDRESS_WAIT_INFINITE && monotonic_nanoseconds()? >= limit {
                return Err(ETIMEDOUT);
            }
            match mochios_posix_client::synchronization::wait_u64_guarded(
                condition.word(),
                before,
                &control.multiplex_generation,
                notification,
                limit,
            ) {
                Ok(_) => {}
                Err(err) if map_kernel_errno(err.raw()) == EINTR => {}
                Err(err) => return Err(map_kernel_errno(err.raw())),
            }
        }
    })();
    let reacquired = unsafe { super::pthread_mutex::pthread_mutex_lock(mutex) };
    let canceled = pending();
    let mut replacement_error = 0;
    condition.end(before, canceled, |address, count| {
        if let Err(err) = mochios_posix_client::synchronization::wake_u64(address, count) {
            replacement_error = map_kernel_errno(err.raw());
        }
    });
    control.cancel_state.store(previous, Ordering::Release);
    // All internal guards are gone before thread exit, which does not unwind.
    if reacquired != 0 {
        return reacquired;
    }
    // Use the same decision for replacement notification and cancellation.
    // A new request racing after this completion decision remains pending;
    // a second test here could cancel after consuming an unreplaced signal.
    if canceled {
        finish_thread(control, usize::MAX as *mut c_void);
    }
    result.err().unwrap_or(replacement_error)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_wait(cond: *mut Condition, mutex: *mut Mutex) -> c_int {
    unsafe { wait(cond, mutex, None, ptr::null()) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_timedwait(
    cond: *mut Condition,
    mutex: *mut Mutex,
    time: *const Timespec,
) -> c_int {
    if time.is_null() {
        return EINVAL;
    }
    unsafe { wait(cond, mutex, None, time) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_cond_clockwait(
    cond: *mut Condition,
    mutex: *mut Mutex,
    clock: u64,
    time: *const Timespec,
) -> c_int {
    if time.is_null() {
        return EINVAL;
    }
    let Ok(clock) = c_int::try_from(clock) else {
        return EINVAL;
    };
    unsafe { wait(cond, mutex, Some(clock), time) }
}
