//! Thread-owned nesting counter for the optional native upcall defer word.
use core::{
    marker::PhantomData,
    sync::atomic::{AtomicU32, Ordering},
};

/// Delays asynchronous callbacks while a thread owns runtime-internal state.
/// The same counter must be registered in that thread's native upcall config.
/// No RPC, allocation, or syscall is performed on entry or exit.
#[must_use]
pub struct Guard<'a> {
    word: &'a AtomicU32,
    _thread_bound: PhantomData<*mut ()>,
}

impl<'a> Guard<'a> {
    /// Returns None rather than wrapping an exhausted nesting count to zero.
    pub fn enter(word: &'a AtomicU32) -> Option<Self> {
        word.fetch_update(Ordering::AcqRel, Ordering::Acquire, |depth| {
            depth.checked_add(1)
        })
        .ok()?;
        Some(Self {
            word,
            _thread_bound: PhantomData,
        })
    }
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.word.fetch_sub(1, Ordering::Release);
    }
}
