//! Observe the native normal scheduling class without granting new authority.
use super::*;

/// Return the scheduling policy and priority of a live process-local pthread.
/// The current native scheduler supports SCHED_OTHER with priority zero only.
/// Returns a pthread error number directly, preserving errno.
///
/// # Safety
/// `policy` and `parameter` must designate writable output storage.
#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_getschedparam(
    thread: Pthread,
    policy: *mut c_int,
    parameter: *mut SchedParam,
) -> c_int {
    let result = (|| {
        if policy.is_null() || parameter.is_null() {
            return Err(EINVAL);
        }
        register_current_thread().ok_or(EAGAIN)?;
        thread_reference::with_live_token(thread, |_| ())?;
        user_copy::write(policy.cast(), &0i32.to_ne_bytes())?;
        user_copy::write(parameter.cast(), &0i32.to_ne_bytes())
    })();
    result.err().unwrap_or(0)
}

/// Set the supported SCHED_OTHER/zero-priority policy on a live pthread.
/// Realtime policies fail with ENOTSUP; no priority change or privilege grant
/// is simulated. Invalid policy/priority pairs fail with EINVAL.
///
/// # Safety
/// `parameter` must designate a readable sched_param.
#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_setschedparam(
    thread: Pthread,
    policy: c_int,
    parameter: *const SchedParam,
) -> c_int {
    let result = (|| {
        if parameter.is_null() {
            return Err(EINVAL);
        }
        let mut bytes = [0; 4];
        user_copy::read(parameter.cast(), &mut bytes)?;
        let priority = i32::from_ne_bytes(bytes);
        register_current_thread().ok_or(EAGAIN)?;
        thread_reference::with_live_token(thread, |_| ())?;
        match policy {
            0 if priority == 0 => Ok(()),
            0 => Err(EINVAL),
            1 | 2 => Err(ENOTSUP),
            _ => Err(EINVAL),
        }
    })();
    result.err().unwrap_or(0)
}
