//! Public newlib pthread mutex ABI. No service RPC or cancellation point.

use super::*;
use mochios_posix_client::pthread_mutex::{self as state, Error, Mutex};

#[repr(C)]
pub struct Attribute {
    initialized: c_int,
    kind: c_int,
    shared: c_int,
}

fn error(error: Error) -> c_int {
    match error {
        Error::Invalid => EINVAL,
        Error::Busy => EBUSY,
        Error::Deadlock => EDEADLK,
        Error::NotOwner => EPERM,
        Error::RecursionLimit => EAGAIN,
    }
}

fn owner() -> Result<u64, c_int> {
    native_thread_id().map_err(|err| map_kernel_errno(err.raw()))
}

unsafe fn attribute<'a>(attr: *const Attribute) -> Result<&'a Attribute, c_int> {
    let attr = unsafe { attr.as_ref() }.ok_or(EINVAL)?;
    if attr.initialized != 1
        || !(state::NORMAL..=state::DEFAULT).contains(&attr.kind)
        || !matches!(attr.shared, 0 | 1)
    {
        return Err(EINVAL);
    }
    Ok(attr)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_init(attr: *mut Attribute) -> c_int {
    if attr.is_null() {
        return EINVAL;
    }
    unsafe {
        attr.write(Attribute {
            initialized: 1,
            kind: state::DEFAULT,
            shared: 0,
        })
    };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_destroy(attr: *mut Attribute) -> c_int {
    if let Err(err) = unsafe { attribute(attr) } {
        return err;
    }
    unsafe { (*attr).initialized = 0 };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_gettype(
    attr: *const Attribute,
    kind: *mut c_int,
) -> c_int {
    let attr = match unsafe { attribute(attr) } {
        Ok(attr) => attr,
        Err(err) => return err,
    };
    if kind.is_null() {
        return EINVAL;
    }
    unsafe { kind.write(attr.kind) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_settype(attr: *mut Attribute, kind: c_int) -> c_int {
    if let Err(err) = unsafe { attribute(attr) } {
        return err;
    }
    if !(state::NORMAL..=state::DEFAULT).contains(&kind) {
        return EINVAL;
    }
    unsafe { (*attr).kind = kind };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutexattr_getpshared(
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
pub unsafe extern "C" fn pthread_mutexattr_setpshared(
    attr: *mut Attribute,
    shared: c_int,
) -> c_int {
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
pub unsafe extern "C" fn pthread_mutex_init(mutex: *mut Mutex, attr: *const Attribute) -> c_int {
    if mutex.is_null() {
        return EINVAL;
    }
    let kind = if attr.is_null() {
        state::DEFAULT
    } else {
        match unsafe { attribute(attr) } {
            Ok(attr) => attr.kind,
            Err(err) => return err,
        }
    };
    unsafe { mutex.write(Mutex::new(kind)) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_destroy(mutex: *mut Mutex) -> c_int {
    let Some(mutex) = (unsafe { mutex.as_ref() }) else {
        return EINVAL;
    };
    mutex.destroy().map_or_else(error, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_trylock(mutex: *mut Mutex) -> c_int {
    let Some(mutex) = (unsafe { mutex.as_ref() }) else {
        return EINVAL;
    };
    let thread = match owner() {
        Ok(thread) => thread,
        Err(err) => return err,
    };
    mutex.try_lock(thread).map_or_else(error, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_lock(mutex: *mut Mutex) -> c_int {
    let Some(mutex) = (unsafe { mutex.as_ref() }) else {
        return EINVAL;
    };
    let thread = match owner() {
        Ok(thread) => thread,
        Err(err) => return err,
    };
    match mutex.lock(
        thread,
        |address, expected| {
            loop {
                match mochios_posix_client::synchronization::wait_u32(
                    address,
                    expected,
                    syscall::ADDRESS_WAIT_INFINITE,
                ) {
                    Ok(_) => return Ok(()),
                    Err(err) => {
                        let err = map_kernel_errno(err.raw());
                        if err != EINTR {
                            return Err(err);
                        }
                    }
                }
            }
        },
        |address| {
            // Preserve the original wait failure; the replacement wake does not
            // turn this failed acquisition into a successful lock operation.
            let _ = mochios_posix_client::synchronization::wake_u32(address, 1);
        },
    ) {
        Ok(result) => result.map_or_else(error, |()| 0),
        Err(err) => err,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_mutex_unlock(mutex: *mut Mutex) -> c_int {
    let Some(mutex) = (unsafe { mutex.as_ref() }) else {
        return EINVAL;
    };
    let thread = match owner() {
        Ok(thread) => thread,
        Err(err) => return err,
    };
    let mut wake_error = 0;
    match mutex.unlock(thread, |address| {
        if let Err(err) = mochios_posix_client::synchronization::wake_u32(address, 1) {
            wake_error = map_kernel_errno(err.raw());
        }
    }) {
        Ok(()) => wake_error,
        Err(err) => error(err),
    }
}
