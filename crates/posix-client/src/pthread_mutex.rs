//! POSIX mutex state, stored inline so shared-memory users share the lock.
//! The caller supplies native wait/wake operations; locking is not a
//! cancellation point and does not involve the POSIX service.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const NORMAL: i32 = 0;
pub const RECURSIVE: i32 = 1;
pub const ERRORCHECK: i32 = 2;
pub const DEFAULT: i32 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Busy,
    Deadlock,
    NotOwner,
    RecursionLimit,
}

#[repr(C)]
pub struct Mutex {
    state: AtomicU32,
    kind: i32,
    owner: AtomicU64,
    depth: AtomicU32,
    initialized: AtomicU32,
    waiters: AtomicU32,
    reserved: u32,
}

const _: [(); 32] = [(); core::mem::size_of::<Mutex>()];
const _: [(); 8] = [(); core::mem::align_of::<Mutex>()];

impl Mutex {
    pub const fn new(kind: i32) -> Self {
        Self {
            state: AtomicU32::new(0),
            kind,
            owner: AtomicU64::new(0),
            depth: AtomicU32::new(0),
            initialized: AtomicU32::new(1),
            waiters: AtomicU32::new(0),
            reserved: 0,
        }
    }

    fn validate(&self, thread: u64) -> Result<(), Error> {
        if thread == 0
            || self.initialized.load(Ordering::Acquire) != 1
            || !(NORMAL..=DEFAULT).contains(&self.kind)
        {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }

    fn relock(&self, thread: u64, trying: bool) -> Result<bool, Error> {
        if self.owner.load(Ordering::Acquire) != thread {
            return Ok(false);
        }
        if self.kind == RECURSIVE {
            let depth = self.depth.load(Ordering::Relaxed);
            self.depth.store(
                depth.checked_add(1).ok_or(Error::RecursionLimit)?,
                Ordering::Relaxed,
            );
            return Ok(true);
        }
        if trying {
            return Err(Error::Busy);
        }
        if self.kind == ERRORCHECK {
            return Err(Error::Deadlock);
        }
        Ok(false) // NORMAL and DEFAULT use normal (non-recursive) locking.
    }

    fn acquired(&self, thread: u64) {
        self.depth.store(1, Ordering::Relaxed);
        self.owner.store(thread, Ordering::Release);
    }

    pub fn check_owner(&self, thread: u64) -> Result<(), Error> {
        self.validate(thread)?;
        if self.owner.load(Ordering::Acquire) == thread {
            Ok(())
        } else {
            Err(Error::NotOwner)
        }
    }

    pub fn try_lock(&self, thread: u64) -> Result<(), Error> {
        self.validate(thread)?;
        if self.relock(thread, true)? {
            return Ok(());
        }
        self.state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::Busy)?;
        self.acquired(thread);
        Ok(())
    }

    pub fn lock<E>(
        &self,
        thread: u64,
        mut wait: impl FnMut(&AtomicU32, u32) -> Result<(), E>,
        mut wake: impl FnMut(&AtomicU32),
    ) -> Result<Result<(), Error>, E> {
        if let Err(error) = self.validate(thread) {
            return Ok(Err(error));
        }
        match self.relock(thread, false) {
            Ok(true) => return Ok(Ok(())),
            Err(error) => return Ok(Err(error)),
            _ => {}
        }
        if self
            .state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            self.acquired(thread);
            return Ok(Ok(()));
        }
        // Counts callers on the slow path, including those between wakes.
        // The guard is safe here: mutex lock never terminates the thread.
        self.waiters.fetch_add(1, Ordering::Relaxed);
        struct Waiter<'a>(&'a AtomicU32);
        impl Drop for Waiter<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::Relaxed);
            }
        }
        let _waiter = Waiter(&self.waiters);
        loop {
            if self.state.swap(2, Ordering::Acquire) == 0 {
                self.acquired(thread);
                return Ok(Ok(()));
            }
            if let Err(error) = wait(&self.state, 2) {
                // An unlock may have selected this waiter just before the
                // wait failed. Do not consume that wake without acquiring:
                // another admitted waiter must get a chance to take the lock.
                // Keep our registration until the handoff is complete.
                if self.state.load(Ordering::Acquire) == 0 {
                    wake(&self.state);
                }
                return Err(error);
            }
        }
    }

    pub fn unlock(&self, thread: u64, mut wake: impl FnMut(&AtomicU32)) -> Result<(), Error> {
        self.validate(thread)?;
        if self.owner.load(Ordering::Acquire) != thread {
            return Err(Error::NotOwner);
        }
        let depth = self.depth.load(Ordering::Relaxed);
        if depth > 1 {
            self.depth.store(depth - 1, Ordering::Relaxed);
            return Ok(());
        }
        self.depth.store(0, Ordering::Relaxed);
        self.owner.store(0, Ordering::Relaxed);
        if self.state.swap(0, Ordering::Release) == 2 {
            wake(&self.state);
        }
        Ok(())
    }

    pub fn destroy(&self) -> Result<(), Error> {
        self.validate(1)?;
        if self.state.load(Ordering::Acquire) != 0 || self.waiters.load(Ordering::Acquire) != 0 {
            return Err(Error::Busy);
        }
        self.initialized.store(0, Ordering::Release);
        Ok(())
    }
}
