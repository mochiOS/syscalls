//! Exclude process snapshots from partially prepared or reclaimed thread state.
use core::sync::atomic::{AtomicU32, Ordering};

const FROZEN: u32 = 1 << 31;

pub struct Gate(AtomicU32);

#[derive(Debug, PartialEq, Eq)]
pub enum EnterError {
    Frozen(u32),
    Exhausted,
}

impl Gate {
    pub const fn new() -> Self {
        Self(AtomicU32::new(0))
    }

    /// Address-wait word. Production callers must not modify it directly.
    pub fn word(&self) -> &AtomicU32 {
        &self.0
    }

    pub fn try_enter(&self) -> Result<Activity<'_>, EnterError> {
        let mut value = self.0.load(Ordering::Acquire);
        loop {
            if value & FROZEN != 0 {
                return Err(EnterError::Frozen(value));
            }
            if value == FROZEN - 1 {
                return Err(EnterError::Exhausted);
            }
            match self.0.compare_exchange_weak(
                value,
                value + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(Activity(self)),
                Err(current) => value = current,
            }
        }
    }

    /// Acquire a snapshot boundary only when no mutation is active. This never
    /// waits, including when called reentrantly from mutation cleanup.
    /// After dropping the returned guard, wake any native waiters on `word()`.
    pub fn try_freeze(&self) -> Option<Freeze<'_>> {
        self.0
            .compare_exchange(0, FROZEN, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Freeze(self))
    }
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Activity<'a>(&'a Gate);
impl Drop for Activity<'_> {
    fn drop(&mut self) {
        self.0.0.fetch_sub(1, Ordering::Release);
    }
}

pub struct Freeze<'a>(&'a Gate);
impl Drop for Freeze<'_> {
    fn drop(&mut self) {
        // The owner must wake any address waiters after this release.
        self.0.0.store(0, Ordering::Release);
    }
}
