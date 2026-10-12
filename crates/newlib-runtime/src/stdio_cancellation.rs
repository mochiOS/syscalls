//! Calling-thread bookkeeping for newlib's nested stdio critical sections.
//! Interrupt a blocked I/O attempt, but exit only after libc releases its locks.
use core::sync::atomic::{AtomicU32, Ordering};

pub struct Scope {
    depth: AtomicU32,
    originally_enabled: AtomicU32,
    interrupted: AtomicU32,
    progressed: AtomicU32,
}

impl Scope {
    pub const fn new() -> Self {
        Self {
            depth: AtomicU32::new(0),
            originally_enabled: AtomicU32::new(0),
            interrupted: AtomicU32::new(0),
            progressed: AtomicU32::new(0),
        }
    }

    pub fn reset(&self) {
        self.depth.store(0, Ordering::Relaxed);
        self.originally_enabled.store(0, Ordering::Relaxed);
        self.interrupted.store(0, Ordering::Relaxed);
        self.progressed.store(0, Ordering::Relaxed);
    }

    pub fn active(&self) -> bool {
        self.depth.load(Ordering::Relaxed) != 0
    }

    /// Only the owning thread enters/leaves; other threads request cancellation
    /// through the TCB, not by changing this bookkeeping. Stdio is not safe to
    /// reenter from an asynchronous signal handler.
    pub fn enter(&self, enabled_before_libc: bool) -> bool {
        let depth = self.depth.load(Ordering::Relaxed);
        let Some(next) = depth.checked_add(1) else {
            return false;
        };
        if depth == 0 {
            self.originally_enabled
                .store(u32::from(enabled_before_libc), Ordering::Relaxed);
            self.interrupted.store(0, Ordering::Relaxed);
            self.progressed.store(0, Ordering::Relaxed);
        }
        self.depth.store(next, Ordering::Relaxed);
        true
    }

    pub fn permits_interrupt(&self) -> bool {
        self.active() && self.originally_enabled.load(Ordering::Relaxed) != 0
    }

    pub fn note_progress(&self) {
        if self.active() {
            self.progressed.store(1, Ordering::Relaxed);
        }
    }

    pub fn note_interruption(&self) {
        if self.permits_interrupt() {
            self.interrupted.store(1, Ordering::Relaxed);
        }
    }

    /// A partial success is reported to the application; cancellation stays
    /// pending. Never hide already transferred bytes by exiting at scope end.
    pub fn leave(&self) -> Option<bool> {
        let depth = self.depth.load(Ordering::Relaxed);
        if depth == 0 {
            return None;
        }
        self.depth.store(depth - 1, Ordering::Relaxed);
        let cancel = depth == 1
            && self.originally_enabled.load(Ordering::Relaxed) != 0
            && self.interrupted.load(Ordering::Relaxed) != 0
            && self.progressed.load(Ordering::Relaxed) == 0;
        if depth == 1 {
            self.reset();
        }
        Some(cancel)
    }
}
