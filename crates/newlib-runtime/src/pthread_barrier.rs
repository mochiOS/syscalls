//! Public barriers: native shared-memory waits, no RPC or cancellation point.

use super::*;
use mochios_posix_client::pthread_barrier::{Arrival, Barrier, Error};
use mochios_posix_client::synchronization;

#[repr(C)]
pub struct Attribute {
    initialized: c_int,
    shared: c_int,
}

fn error(error: Error) -> c_int {
    match error {
        Error::Invalid => EINVAL,
        Error::Busy => EBUSY,
    }
}
fn aligned<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer as usize % core::mem::align_of::<T>() == 0
}
unsafe fn attribute<'a>(pointer: *const Attribute) -> Result<&'a Attribute, c_int> {
    if !aligned(pointer) {
        return Err(EINVAL);
    }
    let attribute = unsafe { &*pointer };
    if attribute.initialized != 1 || !matches!(attribute.shared, 0 | 1) {
        return Err(EINVAL);
    }
    Ok(attribute)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_barrierattr_init(pointer: *mut Attribute) -> c_int {
    if !aligned(pointer) {
        return EINVAL;
    }
    unsafe {
        pointer.write(Attribute {
            initialized: 1,
            shared: 0,
        })
    };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_barrierattr_destroy(pointer: *mut Attribute) -> c_int {
    if let Err(error) = unsafe { attribute(pointer) } {
        return error;
    }
    unsafe { (*pointer).initialized = 0 };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_barrierattr_getpshared(
    pointer: *const Attribute,
    shared: *mut c_int,
) -> c_int {
    let attr = match unsafe { attribute(pointer) } {
        Ok(attr) => attr,
        Err(error) => return error,
    };
    if !aligned(shared) {
        return EINVAL;
    }
    unsafe { shared.write(attr.shared) };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_barrierattr_setpshared(
    pointer: *mut Attribute,
    shared: c_int,
) -> c_int {
    if let Err(error) = unsafe { attribute(pointer) } {
        return error;
    }
    if !matches!(shared, 0 | 1) {
        return EINVAL;
    }
    unsafe { (*pointer).shared = shared };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_barrier_init(
    pointer: *mut Barrier,
    attr: *const Attribute,
    count: u32,
) -> c_int {
    if !aligned(pointer) {
        return EINVAL;
    }
    if !attr.is_null() {
        if let Err(error) = unsafe { attribute(attr) } {
            return error;
        }
    }
    let barrier = match Barrier::new(count) {
        Ok(barrier) => barrier,
        Err(err) => return error(err),
    };
    // Sharing identity comes from native mapping backing, as for mutexes and
    // rwlocks. No process-local token or service-owned synchronization object.
    unsafe { pointer.write(barrier) };
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_barrier_destroy(pointer: *mut Barrier) -> c_int {
    if !aligned(pointer) {
        return EINVAL;
    }
    unsafe { &*pointer }.destroy().map_or_else(error, |()| 0)
}

fn yield_native() {
    let _ = syscall::raw_syscall0(syscall::SyscallNumber::ThreadYield);
}
fn wait(word: &AtomicU64, expected: u64) -> Result<(), c_int> {
    loop {
        match synchronization::wait_u64(word, expected, syscall::ADDRESS_WAIT_INFINITE) {
            Ok(_) => return Ok(()),
            Err(err) => match map_kernel_errno(err.raw()) {
                EINTR => {}               // A barrier never returns EINTR.
                EAGAIN => yield_native(), // A full native wait queue is transient.
                error => return Err(error),
            },
        }
    }
}
fn wake(word: &AtomicU64) -> Result<(), c_int> {
    synchronization::wake_u64(word, usize::MAX)
        .map(|_| ())
        .map_err(|err| map_kernel_errno(err.raw()))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_barrier_wait(pointer: *mut Barrier) -> c_int {
    if !aligned(pointer) {
        return EINVAL;
    }
    let barrier = unsafe { &*pointer };
    let (ticket, serial, notify) = loop {
        match barrier.arrive() {
            Ok(Arrival::Admitted {
                ticket,
                serial,
                wake,
            }) => break (ticket, serial, wake),
            Ok(Arrival::ResetPending { expected }) => {
                if let Err(error) = wait(barrier.entry_word(), expected) {
                    return error;
                }
            }
            Err(err) => return error(err),
        }
    };
    let mut failure = if notify {
        wake(barrier.completion_word()).err()
    } else {
        None
    };
    loop {
        let expected = barrier.completion_word().load(Ordering::Acquire);
        match barrier.passed(ticket) {
            Ok(true) => break,
            Ok(false) => {}
            Err(err) => return error(err), // Concurrent destruction violates lifetime contract.
        }
        if let Err(error) = wait(barrier.completion_word(), expected) {
            // Admission is already committed. Drain the round before returning
            // an error; abandoning this ticket would prevent eventual reset.
            failure.get_or_insert(error);
            yield_native();
        }
    }
    match barrier.leave(ticket) {
        Ok(true) => {
            if let Err(error) = wake(barrier.entry_word()) {
                failure.get_or_insert(error);
            }
        }
        Ok(false) => {}
        Err(err) => return error(err),
    }
    // Pending deferred cancellation remains pending for the next explicit
    // cancellation point. Do not exit after admission or consume a participant.
    failure.unwrap_or(if serial { -1 } else { 0 })
}
