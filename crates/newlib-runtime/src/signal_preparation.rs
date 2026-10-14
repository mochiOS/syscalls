use super::*;
use mochios_posix_client::upcall_guard::Guard;

/// Keep a dequeued delivery private until its handler stack and metadata are
/// ready. The callback trampoline is the commit point, before unmasking:
/// a fork after that point inherits an active handler, not a pending signal.
pub(super) struct Preparation {
    pub(super) control: &'static ThreadControl,
    pub(super) epoch: u64,
    guard: Option<Guard<'static>>,
    begun: bool,
}

impl Preparation {
    pub(super) fn new(control: &'static ThreadControl) -> Result<Self, c_int> {
        let guard = Guard::enter(&control.native_delivery_defer).ok_or(EOVERFLOW)?;
        Ok(Self {
            control,
            epoch: FORK_EPOCH.load(Ordering::Acquire),
            guard: Some(guard),
            begun: false,
        })
    }

    pub(super) fn begin_with(
        &mut self,
        commit: impl FnOnce() -> Result<(), c_int>,
    ) -> Result<bool, c_int> {
        if FORK_EPOCH.load(Ordering::Acquire) != self.epoch {
            return Ok(false);
        }
        commit()?;
        self.begun = true;
        drop(self.guard.take());
        Ok(true)
    }

    pub(super) fn finish(&mut self) -> Result<(), c_int> {
        if self.guard.is_none() {
            self.guard = Some(Guard::enter(&self.control.native_delivery_defer).ok_or(EOVERFLOW)?);
        }
        Ok(())
    }

    pub(super) fn started(&self) -> bool {
        self.begun
    }
}
