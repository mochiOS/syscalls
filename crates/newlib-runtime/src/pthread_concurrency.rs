//! Process-local advisory concurrency level for the native 1:1 thread model.
//! This value neither allocates threads nor changes scheduling or FD limits.
use super::{c_int, EINVAL};
use core::sync::atomic::{AtomicI32, Ordering};

static LEVEL: AtomicI32 = AtomicI32::new(0);

#[unsafe(no_mangle)]
pub extern "C" fn pthread_getconcurrency() -> c_int {
    LEVEL.load(Ordering::Relaxed)
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_setconcurrency(new_level: c_int) -> c_int {
    if new_level < 0 {
        return EINVAL;
    }
    // POSIX requires retaining the hint even for a 1:1 implementation that
    // does not multiplex user threads. No other state is synchronized by it.
    LEVEL.store(new_level, Ordering::Relaxed);
    0
}
