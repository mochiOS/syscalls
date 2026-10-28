//! A join claim is private runtime ownership, including across C callbacks.
//! Never leave a claim behind when cancellation/longjmp abandons this frame.
use super::*;

struct Claim {
    target: &'static ThreadControl,
    epoch: u64,
    armed: bool,
}

impl Claim {
    fn new(thread: Pthread, current: Pthread) -> Result<Self, c_int> {
        if thread == current {
            return Err(EDEADLK);
        }
        let target = thread_control(thread).ok_or(ESRCH)?;
        target
            .joinability
            .compare_exchange(
                THREAD_JOINABLE,
                THREAD_JOIN_CLAIMED,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .map_err(|_| EINVAL)?;
        target.join_waiter.store(current, Ordering::Release);
        Ok(Self {
            target,
            epoch: FORK_EPOCH.load(Ordering::Acquire),
            armed: true,
        })
    }

    fn current(&self) -> Result<(), c_int> {
        if self.epoch == FORK_EPOCH.load(Ordering::Acquire) {
            Ok(())
        } else {
            // Only the calling thread survived fork. The target's copied
            // slot may already hold an unrelated child-side pthread.
            Err(ESRCH)
        }
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        if self.armed && self.current().is_ok() {
            self.target.join_waiter.store(0, Ordering::Release);
            self.target
                .joinability
                .store(THREAD_JOINABLE, Ordering::Release);
        }
    }
}

pub(super) fn join(thread: Pthread, value: *mut *mut c_void) -> c_int {
    pthread_testcancel();
    let Some((current, waiter)) = register_current_thread() else {
        return EAGAIN;
    };
    // SAFETY: Claim owns only process-private state, not a native reference.
    // All target observations and mutations defer callbacks. A copied claim
    // checks its fork epoch before touching a possibly reused target slot;
    // temporary native status observations retain their own delivery guard.
    let result = unsafe {
        io_resources::with_fork_opaque(
            || Claim::new(thread, current),
            |_| true,
            |claim| loop {
                pthread_testcancel();
                let wake = {
                    let _delivery = defer_native_delivery();
                    claim.current()?;
                    let wake = waiter.wait_generation.load(Ordering::Acquire);
                    let target = claim.target;
                    match target.state.load(Ordering::Acquire) {
                        THREAD_EXITED => {
                            if target.creation_pending.load(Ordering::Acquire) == 0
                                && native_thread_retired(target)?
                            {
                                // Capture/publish before consuming the target.
                                // Failure leaves the claim armed for retry.
                                if !value.is_null() {
                                    user_copy::write(
                                        value.cast(),
                                        &target.result.load(Ordering::Acquire).to_ne_bytes(),
                                    )?;
                                }
                                target
                                    .state
                                    .compare_exchange(
                                        THREAD_EXITED,
                                        THREAD_REAPING,
                                        Ordering::AcqRel,
                                        Ordering::Relaxed,
                                    )
                                    .map_err(|_| ESRCH)?;
                                claim.armed = false;
                                release_thread_control(target);
                                return Ok(());
                            }
                            // No target-owned word may be waited on after its
                            // native exit. Yield without delaying callbacks.
                            drop(_delivery);
                            let _ = syscall::raw_syscall0(syscall::SyscallNumber::ThreadYield);
                            continue;
                        }
                        THREAD_STARTING | THREAD_RUNNING => {}
                        _ => return Err(ESRCH),
                    }
                    wake
                };
                // A fork callback before this wait changes the caller's wake
                // word in the child. Its stale expected value cannot park.
                let waited = mochios_posix_client::synchronization::wait_u32(
                    &waiter.wait_generation,
                    wake,
                    syscall::ADDRESS_WAIT_INFINITE,
                );
                let _delivery = defer_native_delivery();
                claim.current()?;
                waited.map_err(|error| map_kernel_errno(error.raw()))?;
            },
        )
    };
    result.err().unwrap_or(0)
}
