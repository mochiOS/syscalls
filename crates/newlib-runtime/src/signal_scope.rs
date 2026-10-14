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
    retired: bool,
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
            retired: false,
            completed: false,
            _pin: PhantomPinned,
            _thread_bound: PhantomData,
        })
    }

    pub(super) fn activate(self: Pin<&mut Self>) -> Result<(), c_int> {
        // Only fields are changed; the pinned record is never moved.
        let scope = unsafe { self.get_unchecked_mut() };
        if scope.active
            || scope.retired
            || scope.control.native_delivery_defer.load(Ordering::Acquire) == 0
        {
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

    fn retire(self: Pin<&mut Self>) -> Result<(), c_int> {
        let scope = unsafe { self.get_unchecked_mut() };
        if !scope.active
            || scope.control.native_delivery_defer.load(Ordering::Acquire) == 0
            || scope.control.active_signal_scope.load(Ordering::Acquire)
                != scope as *mut Self as usize
            || scope.control.active_signal_scope_id.load(Ordering::Acquire) != scope.id
        {
            return Err(EINVAL);
        }
        scope.active = false;
        scope.retired = true;
        scope
            .control
            .active_signal_scope_id
            .store(scope.previous_id, Ordering::Relaxed);
        scope
            .control
            .active_signal_scope
            .store(scope.previous, Ordering::Release);
        Ok(())
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // Drop never moves a record whose address has been published.
        unsafe { Pin::new_unchecked(self) }
            .retire()
            .unwrap_or_else(|error| process_exit(error));
    }
}

/// Verify a saved scope identity using only the current thread's live chain.
/// Zero denotes the continuation outside every handler, never a raw pointer.
///
/// # Safety
/// The caller must be the owning thread and hold its native delivery guard.
/// Every published scope must still be pinned and live. Arbitrary jump-buffer
/// addresses must not be used as chain links.
pub(super) unsafe fn validate_target(control: &ThreadControl, target: u64) -> Result<(), c_int> {
    if control.native_delivery_defer.load(Ordering::Acquire) == 0 {
        return Err(EINVAL);
    }
    let mut pointer = control.active_signal_scope.load(Ordering::Acquire);
    let mut id = control.active_signal_scope_id.load(Ordering::Acquire);
    loop {
        if pointer == 0 {
            return if id == 0 && target == 0 {
                Ok(())
            } else {
                Err(EINVAL)
            };
        }
        let scope = unsafe { &*(pointer as *const Scope) };
        if id == 0
            || scope.id != id
            || !scope.active
            || scope.retired
            || !core::ptr::eq(scope.control, control)
            || scope.previous_id >= id
            || (scope.previous == 0) != (scope.previous_id == 0)
        {
            return Err(EINVAL);
        }
        if id == target {
            return Ok(());
        }
        pointer = scope.previous;
        id = scope.previous_id;
    }
}

/// Finish and unlink only the deliveries abandoned by a nonlocal jump.
/// Validate the entire path first, so a stale target consumes no deliveries.
///
/// # Safety
/// The requirements of `validate_target` apply. After success the caller must
/// not return through an abandoned handler or use its invocation references.
/// On a completion error the caller must fail closed, not retry the jump: the
/// service may already have consumed the request. Parent-epoch tokens copied
/// by fork are never acknowledged in the child.
pub(super) unsafe fn unwind_to(control: &ThreadControl, target: u64) -> Result<(), c_int> {
    unsafe { validate_target(control, target) }?;
    while control.active_signal_scope_id.load(Ordering::Acquire) != target {
        let pointer = control.active_signal_scope.load(Ordering::Acquire);
        // Validation above established provenance and lifetime. Each retirement
        // restores the next validated link while asynchronous delivery is held.
        let mut scope = unsafe { Pin::new_unchecked(&mut *(pointer as *mut Scope)) };
        if !scope.completed {
            scope.as_mut().complete()?;
        }
        scope.retire()?;
    }
    Ok(())
}
