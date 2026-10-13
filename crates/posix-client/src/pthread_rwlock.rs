//! Inline state for newlib's 32-bit rwlock ABI; no process-local handle table.
//! Reader admission is reader-preferred, as permitted without realtime priority
//! scheduling. Unlock by a non-holder remains undefined, not owner-checked.

use core::sync::atomic::{AtomicU32, Ordering};

pub const INITIALIZER: u32 = u32::MAX;
const DESTROYED: u32 = u32::MAX - 1;
const WRITER: u32 = 1 << 31;
pub const MAX_READERS: u32 = WRITER - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    /// Exact snapshot for WaitOnAddress; do not reload a different state before
    /// enqueueing, since that could sleep after acquisition became possible.
    Busy(u32),
    ReaderLimit,
}

fn current(word: &AtomicU32) -> Result<u32, Error> {
    loop {
        let value = word.load(Ordering::Acquire);
        if value == INITIALIZER {
            let _ = word.compare_exchange(INITIALIZER, 0, Ordering::AcqRel, Ordering::Acquire);
            continue;
        }
        return if value <= WRITER {
            Ok(value)
        } else {
            Err(Error::Invalid)
        };
    }
}

pub fn try_read(word: &AtomicU32) -> Result<(), Error> {
    loop {
        let value = current(word)?;
        if value == WRITER {
            return Err(Error::Busy(value));
        }
        if value == MAX_READERS {
            return Err(Error::ReaderLimit);
        }
        if word
            .compare_exchange(value, value + 1, Ordering::Acquire, Ordering::Acquire)
            .is_ok()
        {
            return Ok(());
        }
    }
}

pub fn try_write(word: &AtomicU32) -> Result<(), Error> {
    loop {
        let value = current(word)?;
        if value != 0 {
            return Err(Error::Busy(value));
        }
        if word
            .compare_exchange(0, WRITER, Ordering::Acquire, Ordering::Acquire)
            .is_ok()
        {
            return Ok(());
        }
    }
}

/// Returns true when a release admits waiting readers or writers. Callers must
/// wake address waiters in that case, even if another acquisition has raced in.
pub fn unlock(word: &AtomicU32) -> Result<bool, Error> {
    loop {
        // Unlike acquisition, unlock must not lazily initialize an unused lock.
        let value = word.load(Ordering::Relaxed);
        let next = match value {
            WRITER => 0,
            1..=MAX_READERS => value - 1,
            _ => return Err(Error::Invalid),
        };
        if word
            .compare_exchange(value, next, Ordering::Release, Ordering::Relaxed)
            .is_ok()
        {
            return Ok(next == 0);
        }
    }
}

/// Destroy is valid only with no holders or pending operations. Concurrent
/// destruction/reinitialization is outside the POSIX object's lifetime contract.
pub fn destroy(word: &AtomicU32) -> Result<(), Error> {
    loop {
        let value = word.load(Ordering::Acquire);
        match value {
            0 | INITIALIZER => {}
            1..=WRITER => return Err(Error::Busy(value)),
            _ => return Err(Error::Invalid),
        }
        if word
            .compare_exchange(value, DESTROYED, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Ok(());
        }
    }
}

/// Caller guarantees an uninitialized or destroyed object with exclusive access.
pub fn initialize(word: &AtomicU32) {
    word.store(0, Ordering::Release);
}
