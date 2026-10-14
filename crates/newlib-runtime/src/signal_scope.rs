use super::*;
use core::{
    marker::{PhantomData, PhantomPinned},
    pin::Pin,
};

/// A pinned, thread-owned delivery record. It remains live through completion,
/// not merely through the C handler call. The links never name another thread.
pub(super) struct Scope {
    control: &'static ThreadControl,
    delivery: posix_protocol::SignalDelivery,
    epoch: u64,
    id: u64,
    previous: usize,
    previous_id: u64,
    active: bool,
    completed: bool,
    _pin: PhantomPinned,
    _thread_bound: PhantomData<*mut ()>,
}

impl Scope {
    pub(super) fn new(
        control: &'static ThreadControl,
        delivery: posix_protocol::SignalDelivery,
        epoch: u64,
    ) -> Result<Self, c_int> {
        if control.native_delivery_defer.load(Ordering::Acquire) == 0 {
            return Err(EINVAL);
        }
        // Asynchronous delivery is deferred, but a synchronous fault may reenter.
        // Never reuse an identity allocated by that nested delivery.
        let mut id = control.next_signal_scope_id.load(Ordering::Relaxed);
        loop {
            let next = id.checked_add(1).ok_or(EOVERFLOW)?;
            match control.next_signal_scope_id.compare_exchange_weak(
                id,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => id = current,
            }
        }
        Ok(Self {
            control,
            delivery,
            epoch,
            id,
            previous: 0,
            previous_id: 0,
            active: false,
            completed: false,
            _pin: PhantomPinned,
            _thread_bound: PhantomData,
        })
    }

    pub(super) fn activate(self: Pin<&mut Self>) -> Result<(), c_int> {
        // Only fields are changed; the pinned record is never moved.
        let scope = unsafe { self.get_unchecked_mut() };
        if scope.active || scope.control.native_delivery_defer.load(Ordering::Acquire) == 0 {
            return Err(EINVAL);
        }
        scope.previous = scope.control.active_signal_scope.load(Ordering::Acquire);
        scope.previous_id = scope.control.active_signal_scope_id.load(Ordering::Acquire);
        scope.active = true;
        scope
            .control
            .active_signal_scope_id
            .store(scope.id, Ordering::Relaxed);
        scope
            .control
            .active_signal_scope
            .store(scope as *mut Self as usize, Ordering::Release);
        Ok(())
    }

    pub(super) fn complete(self: Pin<&mut Self>) -> Result<(), c_int> {
        let scope = unsafe { self.get_unchecked_mut() };
        if scope.completed || scope.control.native_delivery_defer.load(Ordering::Acquire) == 0 {
            return Err(EINVAL);
        }
        scope.completed = true; // Never replay an uncertain completion.
        if FORK_EPOCH.load(Ordering::Acquire) != scope.epoch {
            return Ok(());
        }
        posix_client()
            .map_err(map_posix_client_error)
            .and_then(|client| {
                client
                    .complete_signal_delivery(scope.delivery)
                    .map_err(map_posix_client_error)
            })
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if self.control.native_delivery_defer.load(Ordering::Acquire) == 0
            || self.control.active_signal_scope.load(Ordering::Acquire)
                != self as *mut Self as usize
            || self.control.active_signal_scope_id.load(Ordering::Acquire) != self.id
        {
            process_exit(EINVAL);
        }
        self.control
            .active_signal_scope_id
            .store(self.previous_id, Ordering::Relaxed);
        self.control
            .active_signal_scope
            .store(self.previous, Ordering::Release);
    }
}
