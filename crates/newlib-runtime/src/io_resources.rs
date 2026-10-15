//! I/O resources survive returning handlers and are explicitly reclaimed when
//! a C callback abandons the Rust frame. No callback is delayed across a wait.
use super::*;

pub(super) fn with<R>(
    prepare: impl FnOnce() -> Result<R, c_int>,
    operation: impl FnOnce(&mut R) -> Result<isize, c_int>,
) -> Result<isize, c_int> {
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
    drop(native);
    let result = operation(scope.as_mut().resource_mut().unwrap());
    {
        let _native = defer_native_delivery();
        unsafe { scope.as_mut().retire() };
    }
    // Only a scalar result remains. Callers may now check cancellation without
    // hiding a successful prefix or leaving an FD lease/allocation behind.
    result
}
