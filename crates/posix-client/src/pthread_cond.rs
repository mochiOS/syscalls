//! Inline condition state. Registration and notification are serialized so
//! even a notifier that does not hold the application mutex cannot lose an
//! already admitted waiter. Native waiting and cancellation stay in the caller.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Busy,
    TooManyWaiters,
}

#[repr(C)]
pub struct Condition {
    generation: AtomicU64,
    gate: AtomicU32,
    waiters: AtomicU32,
    initialized: AtomicU32,
    clock: i32,
}

const _: [(); 24] = [(); core::mem::size_of::<Condition>()];
const _: [(); 8] = [(); core::mem::align_of::<Condition>()];

struct Gate<'a>(&'a AtomicU32);
impl Drop for Gate<'_> {
    fn drop(&mut self) {
        self.0.store(0, Ordering::Release);
    }
}

impl Condition {
    pub const fn new(clock: i32) -> Self {
        Self {
            generation: AtomicU64::new(0),
            gate: AtomicU32::new(0),
            waiters: AtomicU32::new(0),
            initialized: AtomicU32::new(1),
            clock,
        }
    }
    fn lock(&self) -> Gate<'_> {
        while self
            .gate
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Gate(&self.gate)
    }
    pub fn clock(&self) -> Result<i32, Error> {
        if self.initialized.load(Ordering::Acquire) != 1 || !matches!(self.clock, 1 | 4) {
            Err(Error::Invalid)
        } else {
            Ok(self.clock)
        }
    }
    pub fn word(&self) -> &AtomicU64 {
        &self.generation
    }
    pub fn begin(&self) -> Result<u64, Error> {
        let _gate = self.lock();
        self.clock()?;
        let count = self.waiters.load(Ordering::Relaxed);
        self.waiters.store(
            count.checked_add(1).ok_or(Error::TooManyWaiters)?,
            Ordering::Relaxed,
        );
        Ok(self.generation.load(Ordering::Relaxed))
    }
    pub fn notify(&self, all: bool, mut wake: impl FnMut(&AtomicU64, usize)) -> Result<(), Error> {
        let _gate = self.lock();
        self.clock()?;
        let waiting = self.waiters.load(Ordering::Relaxed) != 0;
        if waiting {
            self.generation.fetch_add(1, Ordering::Release);
        }
        // Keep admission closed through wake: a newer waiter must not steal
        // a notification issued for the already admitted generation.
        if waiting {
            wake(&self.generation, if all { usize::MAX } else { 1 });
        }
        Ok(())
    }
    /// Must run before acting on cancellation: thread exit does not unwind
    /// Rust guards. A canceled waiter passes on any concurrently issued signal.
    pub fn end(&self, before: u64, canceled: bool, mut wake: impl FnMut(&AtomicU64, usize)) {
        let _gate = self.lock();
        let count = self.waiters.load(Ordering::Relaxed);
        debug_assert!(count != 0);
        self.waiters.store(count - 1, Ordering::Relaxed);
        let replace = canceled && count > 1 && self.generation.load(Ordering::Acquire) != before;
        if replace {
            // New-generation waiters may have registered while this caller
            // was reacquiring its mutex. Wake all so one of them cannot steal
            // the replacement; unchanged-generation callers simply wait again.
            wake(&self.generation, usize::MAX);
        }
    }
    pub fn destroy(&self) -> Result<(), Error> {
        let _gate = self.lock();
        self.clock()?;
        if self.waiters.load(Ordering::Relaxed) != 0 {
            return Err(Error::Busy);
        }
        self.initialized.store(0, Ordering::Release);
        Ok(())
    }
}
