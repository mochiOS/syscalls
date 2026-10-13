//! In-place POSIX spin state; no registry, RPC or native object allocation.

use core::sync::atomic::{AtomicU32, Ordering};

pub const DESTROYED: u32 = u32::MAX;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Busy,
}

/// Lifecycle initialization requires exclusive access to the object.
pub fn initialize(word: &AtomicU32) {
    word.store(0, Ordering::Release);
}

pub fn try_lock(word: &AtomicU32) -> Result<(), Error> {
    match word.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed) {
        Ok(_) => Ok(()),
        Err(1) => Err(Error::Busy),
        Err(_) => Err(Error::Invalid),
    }
}

/// Unlocking without ownership is outside the POSIX contract; this state
/// does not introduce native thread IDs or a process-local ownership table.
pub fn unlock(word: &AtomicU32) -> Result<(), Error> {
    word.compare_exchange(1, 0, Ordering::Release, Ordering::Relaxed)
        .map(|_| ())
        .map_err(|_| Error::Invalid)
}

pub fn destroy(word: &AtomicU32) -> Result<(), Error> {
    match word.compare_exchange(0, DESTROYED, Ordering::AcqRel, Ordering::Relaxed) {
        Ok(_) => Ok(()),
        Err(1) => Err(Error::Busy),
        Err(_) => Err(Error::Invalid),
    }
}
