use super::*;
use mochios_posix_client::thread_lifecycle::{Activity, EnterError, Freeze, Gate};

static GATE: Gate = Gate::new();

pub(super) fn stable_revision() -> Option<u32> {
    GATE.stable_revision()
}

pub(super) struct Mutation {
    // Release the activity before permitting a deferred callback to fork.
    _activity: Activity<'static>,
    _delivery: Option<mochios_posix_client::upcall_guard::Guard<'static>>,
}

pub(super) fn mutate() -> Mutation {
    let delivery = defer_native_delivery();
    loop {
        match GATE.try_enter() {
            Ok(activity) => {
                return Mutation {
                    _activity: activity,
                    _delivery: delivery,
                };
            }
            Err(EnterError::Frozen(value)) => native_mutex_wait(GATE.word(), value),
            Err(EnterError::Exhausted) => process_exit(EOVERFLOW),
        }
    }
}

pub(super) struct Capture {
    lease: Option<Freeze<'static>>,
    _delivery: Option<mochios_posix_client::upcall_guard::Guard<'static>>,
}

pub(super) fn capture() -> Result<Capture, c_int> {
    let delivery = defer_native_delivery();
    let lease = GATE.try_freeze().ok_or(EAGAIN)?;
    Ok(Capture {
        lease: Some(lease),
        _delivery: delivery,
    })
}

impl Drop for Capture {
    fn drop(&mut self) {
        drop(self.lease.take());
        native_mutex_wake_all(GATE.word());
    }
}
