//! Public newlib rwlock ABI; waiting uses native memory backing, not an RPC.

use super::*;
use mochios_posix_client::pthread_rwlock::{self as state, Error};
use mochios_posix_client::synchronization::{self, WaitStatus};

#[repr(C)]
pub struct Attribute {
    initialized: c_int,
    shared: c_int,
}
const ETIMEDOUT: c_int = 116;

fn error(error: Error) -> c_int {
    match error {
        Error::Invalid => EINVAL,
        Error::Busy(_) => EBUSY,
        Error::ReaderLimit => EAGAIN,
    }
}

unsafe fn attribute<'a>(attr: *const Attribute) -> Result<&'a Attribute, c_int> {
    if attr.is_null() || attr as usize % core::mem::align_of::<Attribute>() != 0 {
        return Err(EINVAL);
    }
    let attr = unsafe { &*attr };
    if attr.initialized != 1 || !matches!(attr.shared, 0 | 1) {
        return Err(EINVAL);
    }
    Ok(attr)
}
unsafe fn word<'a>(lock: *mut AtomicU32) -> Result<&'a AtomicU32, c_int> {
    if lock.is_null() || lock as usize % core::mem::align_of::<AtomicU32>() != 0 {
        return Err(EINVAL);
    }
    Ok(unsafe { &*lock })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlockattr_init(attr: *mut Attribute) -> c_int {
    if attr.is_null() || attr as usize % core::mem::align_of::<Attribute>() != 0 {
        return EINVAL;
    }
    unsafe {
        attr.write(Attribute {
            initialized: 1,
            shared: 0,
        })
    };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlockattr_destroy(attr: *mut Attribute) -> c_int {
    if let Err(error) = unsafe { attribute(attr) } {
        return error;
    }
    unsafe { (*attr).initialized = 0 };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlockattr_getpshared(
    attr: *const Attribute,
    shared: *mut c_int,
) -> c_int {
    let attr = match unsafe { attribute(attr) } {
        Ok(attr) => attr,
        Err(error) => return error,
    };
    if shared.is_null() {
        return EINVAL;
    }
    unsafe { shared.write(attr.shared) };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlockattr_setpshared(
    attr: *mut Attribute,
    shared: c_int,
) -> c_int {
    if let Err(error) = unsafe { attribute(attr) } {
        return error;
    }
    if !matches!(shared, 0 | 1) {
        return EINVAL;
    }
    unsafe { (*attr).shared = shared };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_init(
    lock: *mut AtomicU32,
    attr: *const Attribute,
) -> c_int {
    if !attr.is_null() {
        if let Err(error) = unsafe { attribute(attr) } {
            return error;
        }
    }
    if lock.is_null() || lock as usize % core::mem::align_of::<AtomicU32>() != 0 {
        return EINVAL;
    }
    // Shared/private wake identity comes from the mapped native backing, as
    // with the existing pthread mutex implementation. No local token table.
    unsafe { lock.write(AtomicU32::new(0)) };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_destroy(lock: *mut AtomicU32) -> c_int {
    match unsafe { word(lock) } {
        Ok(lock) => state::destroy(lock).map_or_else(error, |()| 0),
        Err(error) => error,
    }
}

unsafe fn acquire(
    lock: *mut AtomicU32,
    write: bool,
    timeout: Option<(u64, *const Timespec)>,
    attempt_only: bool,
) -> c_int {
    if let Some((clock, _)) = timeout {
        if !matches!(clock, 1 | 4) {
            return EINVAL;
        }
    }
    let lock = match unsafe { word(lock) } {
        Ok(lock) => lock,
        Err(error) => return error,
    };
    let mut absolute = None;
    loop {
        let expected = match if write {
            state::try_write(lock)
        } else {
            state::try_read(lock)
        } {
            Ok(()) => return 0,
            Err(Error::Busy(value)) if !attempt_only => value,
            Err(err) => return error(err),
        };
        let deadline = if let Some((clock, time)) = timeout {
            let value = match absolute {
                Some(value) => value,
                None => {
                    let Some(time) = (unsafe { time.as_ref() }) else {
                        return EINVAL;
                    };
                    if !(0..1_000_000_000).contains(&time.tv_nsec) {
                        return EINVAL;
                    }
                    let value =
                        (i128::from(time.tv_sec) * 1_000_000_000 + i128::from(time.tv_nsec)).max(0);
                    let value = match u64::try_from(value) {
                        Ok(value) => value,
                        Err(_) => return EOVERFLOW,
                    };
                    absolute = Some(value);
                    value
                }
            };
            let deadline = match super::pthread_time::deadline(clock as c_int, value) {
                Ok(value) => value,
                Err(error) => return error,
            };
            let now = match monotonic_nanoseconds() {
                Ok(now) => now,
                Err(error) => return error,
            };
            if deadline <= now {
                return ETIMEDOUT;
            }
            deadline
        } else {
            syscall::ADDRESS_WAIT_INFINITE
        };
        // Neither regular nor timed rwlock acquisition is a cancellation point.
        match synchronization::wait_u32(lock, expected, deadline) {
            Ok(WaitStatus::DeadlineReached) => return ETIMEDOUT,
            Ok(_) => {}
            Err(err) => {
                let err = map_kernel_errno(err.raw());
                if err != EINTR {
                    return err;
                }
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_rdlock(lock: *mut AtomicU32) -> c_int {
    unsafe { acquire(lock, false, None, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_wrlock(lock: *mut AtomicU32) -> c_int {
    unsafe { acquire(lock, true, None, false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_tryrdlock(lock: *mut AtomicU32) -> c_int {
    unsafe { acquire(lock, false, None, true) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_trywrlock(lock: *mut AtomicU32) -> c_int {
    unsafe { acquire(lock, true, None, true) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_timedrdlock(
    lock: *mut AtomicU32,
    time: *const Timespec,
) -> c_int {
    unsafe { acquire(lock, false, Some((1, time)), false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_timedwrlock(
    lock: *mut AtomicU32,
    time: *const Timespec,
) -> c_int {
    unsafe { acquire(lock, true, Some((1, time)), false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_clockrdlock(
    lock: *mut AtomicU32,
    clock: u64,
    time: *const Timespec,
) -> c_int {
    unsafe { acquire(lock, false, Some((clock, time)), false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_clockwrlock(
    lock: *mut AtomicU32,
    clock: u64,
    time: *const Timespec,
) -> c_int {
    unsafe { acquire(lock, true, Some((clock, time)), false) }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_rwlock_unlock(lock: *mut AtomicU32) -> c_int {
    let lock = match unsafe { word(lock) } {
        Ok(lock) => lock,
        Err(error) => return error,
    };
    match state::unlock(lock) {
        Ok(true) => synchronization::wake_u32(lock, usize::MAX)
            .map_or_else(|err| map_kernel_errno(err.raw()), |_| 0),
        Ok(false) => 0,
        Err(err) => error(err),
    }
}
