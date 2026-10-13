//! Reusable in-place barrier rounds. Counters reset only after all admitted
//! tickets have departed, so a slow waiter cannot confuse old and new rounds.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Busy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival {
    Admitted {
        ticket: u64,
        serial: bool,
        wake: bool,
    },
    ResetPending {
        expected: u64,
    },
}

/// The bound allows deterministic wrap/reset tests. Production uses half the
/// u64 range and rounds down to a whole number of participant groups.
#[repr(C)]
pub struct Barrier<const RESET_BOUND: u64 = { u64::MAX / 2 }> {
    count: u32,
    initialized: AtomicU32,
    entered: AtomicU64,
    completed: AtomicU64,
    departed: AtomicU64,
}

const _: [(); 32] = [(); core::mem::size_of::<Barrier>()];
const _: [(); 8] = [(); core::mem::align_of::<Barrier>()];

impl<const RESET_BOUND: u64> Barrier<RESET_BOUND> {
    pub fn new(count: u32) -> Result<Self, Error> {
        if count == 0 || u64::from(count) > RESET_BOUND {
            return Err(Error::Invalid);
        }
        Ok(Self {
            count,
            initialized: AtomicU32::new(1),
            entered: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            departed: AtomicU64::new(0),
        })
    }

    fn limit(&self) -> u64 {
        RESET_BOUND - RESET_BOUND % u64::from(self.count)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.count == 0
            || u64::from(self.count) > RESET_BOUND
            || self.initialized.load(Ordering::Acquire) != 1
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }

    /// Each admitted ticket must be kept until its round passes and then left
    /// exactly once. ResetPending admits nothing and can wait on `entry_word`.
    pub fn arrive(&self) -> Result<Arrival, Error> {
        self.validate()?;
        loop {
            let entered = self.entered.load(Ordering::Acquire);
            if entered >= self.limit() {
                return Ok(Arrival::ResetPending { expected: entered });
            }
            let ticket = entered + 1;
            // All arrivals publish their preceding application writes; the
            // final arrival acquires the chain before publishing completion.
            if self
                .entered
                .compare_exchange(entered, ticket, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            let serial = ticket % u64::from(self.count) == 0;
            let mut wake = false;
            if serial {
                let mut before = self.completed.load(Ordering::Acquire);
                while before < ticket {
                    match self.completed.compare_exchange(
                        before,
                        ticket,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            wake = true;
                            break;
                        }
                        Err(value) => before = value,
                    }
                }
            }
            return Ok(Arrival::Admitted {
                ticket,
                serial,
                wake,
            });
        }
    }

    pub fn passed(&self, ticket: u64) -> Result<bool, Error> {
        self.validate()?;
        if ticket == 0 || ticket > self.limit() {
            return Err(Error::Invalid);
        }
        Ok(self.completed.load(Ordering::Acquire) >= ticket)
    }

    /// Caller owns this admitted ticket, has observed completion, and has not
    /// left before. `true` requests a broadcast on entry_word after reset.
    pub fn leave(&self, ticket: u64) -> Result<bool, Error> {
        if !self.passed(ticket)? {
            return Err(Error::Invalid);
        }
        let departed = self.departed.fetch_add(1, Ordering::AcqRel) + 1;
        if departed != self.limit() {
            return Ok(false);
        }
        // No outstanding admitted ticket can still inspect completed. New
        // entrants observe the final release only after the whole reset.
        self.completed.store(0, Ordering::Relaxed);
        self.departed.store(0, Ordering::Relaxed);
        self.entered.store(0, Ordering::Release);
        Ok(true)
    }

    pub fn entry_word(&self) -> &AtomicU64 {
        &self.entered
    }
    pub fn completion_word(&self) -> &AtomicU64 {
        &self.completed
    }

    /// Exclusive lifecycle operation. Concurrent destroy/reinit is outside
    /// the POSIX lifetime contract; unfinished participants report Busy.
    pub fn destroy(&self) -> Result<(), Error> {
        self.validate()?;
        if self.entered.load(Ordering::Acquire) != self.departed.load(Ordering::Acquire) {
            return Err(Error::Busy);
        }
        self.initialized.store(0, Ordering::Release);
        Ok(())
    }
}
