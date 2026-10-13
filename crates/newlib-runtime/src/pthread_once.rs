//! Newlib pthread_once: initializer cleanup and non-cancellable waiters.

use super::*;
use mochios_posix_client::pthread_once::{self as state, Claim};

#[repr(C)]
pub struct Once {
    initialized: c_int,
    executed: AtomicU32,
}

unsafe extern "C" fn reset(argument: *mut c_void) {
    let once = unsafe { &*argument.cast::<Once>() };
    state::abort(&once.executed);
    let _ = __mochios_wake_address_u32(&once.executed, usize::MAX);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_once(
    once: *mut Once,
    routine: Option<unsafe extern "C" fn()>,
) -> c_int {
    if once.is_null() || once as usize % core::mem::align_of::<Once>() != 0 {
        return EINVAL;
    }
    let Some(routine) = routine else {
        return EINVAL;
    };
    let once = unsafe { &*once };
    if once.initialized != 1 {
        return EINVAL;
    }
    loop {
        match state::claim(&once.executed) {
            Ok(Claim::Complete) => return 0,
            Ok(Claim::Wait) => {
                // pthread_once is not itself a cancellation point. Signals or
                // pending deferred cancellation must not cause an EINTR return.
                let result =
                    __mochios_wait_on_address_u32(&once.executed, state::RUNNING, u64::MAX);
                if (result as i64) < 0 {
                    let error = map_kernel_errno(result as i64);
                    if error != EINTR {
                        return error;
                    }
                }
            }
            Ok(Claim::Initialize) => {
                let Some((_, control)) = register_current_thread() else {
                    state::abort(&once.executed);
                    let _ = __mochios_wake_address_u32(&once.executed, usize::MAX);
                    return EAGAIN;
                };
                let mut cleanup = MaybeUninit::<thread_cleanup::Context>::uninit();
                let cancel_type = control.cancel_type.load(Ordering::Acquire) as c_int;
                unsafe {
                    thread_cleanup::push(
                        &control.cleanup_head,
                        cleanup.as_mut_ptr(),
                        Some(reset),
                        once as *const Once as *mut c_void,
                        cancel_type,
                    );
                    routine();
                    let _ = thread_cleanup::pop(&control.cleanup_head, cleanup.as_mut_ptr(), false);
                }
                state::complete(&once.executed);
                let _ = __mochios_wake_address_u32(&once.executed, usize::MAX);
                return 0;
            }
            Err(error) => return error,
        }
    }
}
