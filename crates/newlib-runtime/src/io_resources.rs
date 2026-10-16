//! I/O resources survive returning handlers and are explicitly reclaimed when
//! a C callback abandons the Rust frame. No callback is delayed across a wait.
use super::*;

pub(super) fn with<R, T: Copy>(
    prepare: impl FnOnce() -> Result<R, c_int>,
    operation: impl FnOnce(&mut R) -> Result<T, c_int>,
) -> Result<T, c_int> {
    with_initialized(prepare, |_| Ok(()), operation)
}

/// Initialize caller-dependent data only after publishing ownership, but
/// before reopening asynchronous delivery. A synchronous fault may abandon
/// initialization, so partially prepared resources must already be tracked.
pub(super) fn with_initialized<R, T: Copy>(
    prepare: impl FnOnce() -> Result<R, c_int>,
    initialize: impl FnOnce(&mut R) -> Result<(), c_int>,
    operation: impl FnOnce(&mut R) -> Result<T, c_int>,
) -> Result<T, c_int> {
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let native = defer_native_delivery();
    let mut scope = core::pin::pin!(callback_resources::Scope::new(
        &control.callback_resources,
        control.active_signal_scope_id.load(Ordering::Acquire),
        prepare()?
    ));
    // Pin and publish before reopening delivery. The operation may invoke C
    // only through the runtime's nested signal contexts, never directly.
    unsafe { scope.as_mut().activate() };
    if let Err(error) = initialize(scope.as_mut().resource_mut().unwrap()) {
        unsafe { scope.as_mut().retire() };
        return Err(error);
    }
    drop(native);
    let result = operation(scope.as_mut().resource_mut().unwrap());
    {
        let _native = defer_native_delivery();
        unsafe { scope.as_mut().retire() };
    }
    // Only a Copy result remains. Callers may now check cancellation without
    // hiding a successful prefix or leaving an FD lease/allocation behind.
    result
}
