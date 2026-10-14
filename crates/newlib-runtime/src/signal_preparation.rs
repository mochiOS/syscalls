use super::*;
use mochios_posix_client::upcall_guard::Guard;

/// Keep a dequeued delivery private until its handler stack and metadata are
/// ready. The callback trampoline is the commit point, before unmasking:
/// a fork after that point inherits an active handler, not a pending signal.
pub(super) struct Preparation {
    pub(super) control: &'static ThreadControl,
    pub(super) epoch: u64,
    guard: Option<Guard<'static>>,
}

impl Preparation {
    pub(super) fn new(control: &'static ThreadControl) -> Result<Self, c_int> {
        let guard = Guard::enter(&control.native_delivery_defer).ok_or(EOVERFLOW)?;
        Ok(Self {
            control,
            epoch: FORK_EPOCH.load(Ordering::Acquire),
            guard: Some(guard),
        })
    }

    pub(super) fn begin(&mut self) -> bool {
        if FORK_EPOCH.load(Ordering::Acquire) != self.epoch {
            return false;
        }
        drop(self.guard.take());
        true
    }

    pub(super) fn started(&self) -> bool {
        self.guard.is_none()
    }
}
