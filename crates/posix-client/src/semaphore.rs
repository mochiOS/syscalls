//! In-place POSIX counting state. Address backing supplies sharing identity;
//! named-object discovery and cancellation policy belong above this counter.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const VALUE_MAX: u32 = i32::MAX as u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Overflow,
}

#[repr(C)]
pub struct Semaphore {
    count: AtomicU64,
    initialized: AtomicU32,
    reserved: u32,
}

const _: [(); 16] = [(); core::mem::size_of::<Semaphore>()];
const _: [(); 8] = [(); core::mem::align_of::<Semaphore>()];

impl Semaphore {
    pub fn new(value: u32, shared: bool) -> Result<Self, Error> {
        if value > VALUE_MAX {
            return Err(Error::Invalid);
        }
        Ok(Self {
            count: AtomicU64::new(u64::from(value)),
            initialized: AtomicU32::new(if shared { 2 } else { 1 }),
            reserved: 0,
        })
    }

    fn validate(&self) -> Result<(), Error> {
        if self.reserved != 0 || !matches!(self.initialized.load(Ordering::Acquire), 1 | 2) {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    pub fn value(&self) -> Result<u32, Error> {
        self.validate()?;
        let count = self.count.load(Ordering::Acquire);
        if count > u64::from(VALUE_MAX) {
            return Err(Error::Invalid);
        }
        Ok(count as u32)
    }

    /// A successful CAS commits one token to the caller. A cancellation-point
    /// adapter must check pending cancellation before this operation, and must
    /// not terminate after success before reporting ownership to the caller.
    pub fn try_take(&self) -> Result<bool, Error> {
        self.validate()?;
        loop {
            let count = self.count.load(Ordering::Acquire);
            if count > u64::from(VALUE_MAX) {
                return Err(Error::Invalid);
            }
            if count == 0 {
                return Ok(false);
            }
            if self
                .count
                .compare_exchange(count, count - 1, Ordering::Acquire, Ordering::Acquire)
                .is_ok()
            {
                return Ok(true);
            }
        }
    }

    /// No allocation, table lock, TLS registration or RPC: sem_post must remain
    /// usable from a signal handler. The adapter must broadcast native wakes;
    /// a single selected waiter could exit on cancellation/signal and strand
    /// other waiters while leaving this posted token available.
    pub fn post(&self) -> Result<(), Error> {
        self.validate()?;
        loop {
            let count = self.count.load(Ordering::Relaxed);
            if count > u64::from(VALUE_MAX) {
                return Err(Error::Invalid);
            }
            if count == u64::from(VALUE_MAX) {
                return Err(Error::Overflow);
            }
            if self
                .count
                .compare_exchange(count, count + 1, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    /// Only wait while this word remains zero. Guard it with the calling
    /// thread's notification generation to close cancellation admission races.
    pub fn word(&self) -> &AtomicU64 {
        &self.count
    }

    /// Caller guarantees no active operations/waiters, as required by POSIX.
    /// Positive unused tokens do not prevent destruction.
    pub fn destroy(&self) -> Result<(), Error> {
        self.validate()?;
        self.initialized.swap(0, Ordering::AcqRel);
        Ok(())
    }
}
