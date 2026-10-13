//! Public spin ABI. Fast acquisition stays in userspace; long contention
//! periodically yields the CPU without becoming a cancellation point.

use super::*;
use mochios_posix_client::pthread_spin::{self as state, Error};

fn error(error: Error) -> c_int {
    match error {
        Error::Invalid => EINVAL,
        Error::Busy => EBUSY,
    }
}
unsafe fn word<'a>(pointer: *mut AtomicU32) -> Result<&'a AtomicU32, c_int> {
    if pointer.is_null() || pointer as usize % core::mem::align_of::<AtomicU32>() != 0 {
        return Err(EINVAL);
    }
    Ok(unsafe { &*pointer })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_spin_init(pointer: *mut AtomicU32, shared: c_int) -> c_int {
    if pointer.is_null()
        || pointer as usize % core::mem::align_of::<AtomicU32>() != 0
        || !matches!(shared, 0 | 1)
    {
        return EINVAL;
    }
    // Write, rather than borrowing/reading an uninitialized C spin object.
    unsafe { pointer.write(AtomicU32::new(0)) };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_spin_destroy(pointer: *mut AtomicU32) -> c_int {
    match unsafe { word(pointer) } {
        Ok(word) => state::destroy(word).map_or_else(error, |()| 0),
        Err(err) => err,
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_spin_trylock(pointer: *mut AtomicU32) -> c_int {
    match unsafe { word(pointer) } {
        Ok(word) => state::try_lock(word).map_or_else(error, |()| 0),
        Err(err) => err,
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_spin_unlock(pointer: *mut AtomicU32) -> c_int {
    match unsafe { word(pointer) } {
        Ok(word) => state::unlock(word).map_or_else(error, |()| 0),
        Err(err) => err,
    }
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_spin_lock(pointer: *mut AtomicU32) -> c_int {
    let word = match unsafe { word(pointer) } {
        Ok(word) => word,
        Err(err) => return err,
    };
    let mut attempts = 0;
    loop {
        match state::try_lock(word) {
            Ok(()) => return 0,
            Err(Error::Busy) => {
                core::hint::spin_loop();
                attempts += 1;
                if attempts == 256 {
                    let _ = syscall::raw_syscall0(syscall::SyscallNumber::ThreadYield);
                    attempts = 0;
                }
            }
            Err(err) => return error(err),
        }
    }
}
