//! Process-local cancellation policy over the generic native upcall path.
//! Caller-side references and delivery guards are gone before cleanup runs.
use super::*;

fn asynchronous_pending(control: &ThreadControl) -> bool {
    control.cancel_state.load(Ordering::Acquire) == PTHREAD_CANCEL_ENABLE
        && control.cancel_type.load(Ordering::Acquire) == PTHREAD_CANCEL_ASYNCHRONOUS
        && control.cancel_pending.load(Ordering::Acquire) != 0
}

/// Only while with_live_token holds the target's reference retirement lock.
/// No temporary native reference or app signal is allocated for notification.
pub(super) fn notify_async(control: &ThreadControl) -> Result<(), c_int> {
    if !asynchronous_pending(control) {
        return Ok(());
    }
    let handle = control.native_handle.load(Ordering::Acquire);
    if handle == 0 {
        return Err(ESRCH);
    }
    match syscall::raw_syscall2(
        syscall::SyscallNumber::ThreadInterrupt,
        u64::from(handle),
        0,
    )
    .into_result()
    {
        Ok(_) => Ok(()),
        // Every generic notification tests pending cancellation on entry.
        // A full native queue therefore already guarantees such an entry;
        // it is not necessary to discard a notification or spin under a lock.
        Err(error) if error.native_error() == Some(mnu_abi::status::Error::ResourceUnavailable) => {
            Ok(())
        }
        Err(error) if error.native_error() == Some(mnu_abi::status::Error::NotFound) => Err(ESRCH),
        Err(error) => Err(map_kernel_errno(error.raw())),
    }
}

pub(super) fn test_async() {
    let Some((_, control)) = current_thread_control() else {
        return;
    };
    if control.native_delivery_defer.load(Ordering::Acquire) == 0
        && !control.callback_resources.is_deferred()
        && asynchronous_pending(control)
    {
        finish_thread(control, usize::MAX as *mut c_void);
    }
}
