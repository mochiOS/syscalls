//! Exclude process snapshots from partially prepared or reclaimed thread state.
use core::sync::atomic::{AtomicU32, Ordering};

const FROZEN: u32 = 1 << 31;

pub struct Gate {
    state: AtomicU32,
    revision: AtomicU32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnterError {
    Frozen(u32),
    Exhausted,
}

impl Gate {
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(0),
            revision: AtomicU32::new(1),
        }
    }

    /// Address-wait word. Production callers must not modify it directly.
    pub fn word(&self) -> &AtomicU32 {
        &self.state
    }

    /// A cache may reuse an observation only if this revision is unchanged
    /// before and after lookup. Mutations and snapshots invalidate it. At
    /// exhaustion caching stays disabled permanently rather than wrapping.
    pub fn stable_revision(&self) -> Option<u32> {
        let revision = self.revision.load(Ordering::SeqCst);
        (revision != u32::MAX
            && self.state.load(Ordering::SeqCst) == 0
            && self.revision.load(Ordering::SeqCst) == revision)
            .then_some(revision)
    }

    fn invalidate(&self) {
        let _ = self
            .revision
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                Some(value.saturating_add(1))
            });
    }

    pub fn try_enter(&self) -> Result<Activity<'_>, EnterError> {
        let mut value = self.state.load(Ordering::SeqCst);
        loop {
            if value & FROZEN != 0 {
                return Err(EnterError::Frozen(value));
            }
            if value == FROZEN - 1 {
                return Err(EnterError::Exhausted);
            }
            match self.state.compare_exchange_weak(
                value,
                value + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    self.invalidate();
                    return Ok(Activity(self));
                }
                Err(current) => value = current,
            }
        }
    }

    /// Acquire a snapshot boundary only when no mutation is active. This never
    /// waits, including when called reentrantly from mutation cleanup.
    /// After dropping the returned guard, wake any native waiters on `word()`.
    pub fn try_freeze(&self) -> Option<Freeze<'_>> {
        self.state
            .compare_exchange(0, FROZEN, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| {
                self.invalidate();
                Freeze(self)
            })
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
        self.0.state.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct Freeze<'a>(&'a Gate);
impl Drop for Freeze<'_> {
    fn drop(&mut self) {
        // The owner must wake any address waiters after this release.
        self.0.state.store(0, Ordering::SeqCst);
    }
}
