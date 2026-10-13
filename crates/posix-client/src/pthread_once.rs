//! Process-private initialization state for the newlib two-word once ABI.

use core::sync::atomic::{AtomicU32, Ordering};

pub const RUNNING: u32 = 2;
const COMPLETE: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    Initialize,
    Wait,
    Complete,
}

pub fn claim(state: &AtomicU32) -> Result<Claim, i32> {
    loop {
        match state.load(Ordering::Acquire) {
            COMPLETE => return Ok(Claim::Complete),
            RUNNING => return Ok(Claim::Wait),
            0 => {
                if state
                    .compare_exchange(0, RUNNING, Ordering::Acquire, Ordering::Acquire)
                    .is_ok()
                {
                    return Ok(Claim::Initialize);
                }
            }
            _ => return Err(crate::newlib_errno::EINVAL),
        }
    }
}

/// Publish initializer writes before allowing a successful waiter to return.
pub fn complete(state: &AtomicU32) {
    state.store(COMPLETE, Ordering::Release);
}

/// Used by exit/cancellation cleanup, never after normal completion.
pub fn abort(state: &AtomicU32) {
    let _ = state.compare_exchange(RUNNING, 0, Ordering::Release, Ordering::Relaxed);
}
