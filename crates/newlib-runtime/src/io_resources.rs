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
    with_policy(prepare, initialize, operation, |_| false)
}

/// # Safety
/// When allow returns true, R contains only FD pins/private memory and the
/// operation cannot acquire additional native references outside a nested
/// ordinary scope. Otherwise retain the ordinary blocking scope, including
/// during complex I/O and its waits.
pub(super) unsafe fn with_fork_opaque<R, T: Copy>(
    prepare: impl FnOnce() -> Result<R, c_int>,
    allow: impl FnOnce(&R) -> bool,
    operation: impl FnOnce(&mut R) -> Result<T, c_int>,
) -> Result<T, c_int> {
    unsafe { with_initialized_fork_opaque(prepare, |_| Ok(()), allow, operation) }
}

/// Initialize and validate private buffers before publishing fork admission.
///
/// # Safety
/// The same ownership contract as with_fork_opaque applies after initialize
/// returns successfully. Preparation and initialization remain ordinary
/// blockers; no partially initialized owner may be admitted.
pub(super) unsafe fn with_initialized_fork_opaque<R, T: Copy>(
    prepare: impl FnOnce() -> Result<R, c_int>,
    initialize: impl FnOnce(&mut R) -> Result<(), c_int>,
    allow: impl FnOnce(&R) -> bool,
    operation: impl FnOnce(&mut R) -> Result<T, c_int>,
) -> Result<T, c_int> {
    with_policy(prepare, initialize, operation, allow)
}

fn with_policy<R, T: Copy>(
    prepare: impl FnOnce() -> Result<R, c_int>,
    initialize: impl FnOnce(&mut R) -> Result<(), c_int>,
    operation: impl FnOnce(&mut R) -> Result<T, c_int>,
    fork_opaque: impl FnOnce(&R) -> bool,
) -> Result<T, c_int> {
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let native = defer_native_delivery();
    let mut scope = core::pin::pin!(callback_resources::Scope::new(
        &control.callback_resources,
        control.active_signal_scope_id.load(Ordering::Acquire),
        None::<R>
    ));
    // Pin and publish before reopening delivery. The operation may invoke C
    // only through the runtime's nested signal contexts, never directly.
    unsafe { scope.as_mut().activate() };
    // Publish an empty owner before allocating/opening any resources. A fork
    // must see this preparation even before it has produced its first Handle.
    let initialized = (|| {
        let resource = prepare()?;
        *scope.as_mut().resource_mut().unwrap() = Some(resource);
        initialize(scope.as_mut().resource_mut().unwrap().as_mut().unwrap())
    })();
    if let Err(error) = initialized {
        unsafe { scope.as_mut().retire() };
        return Err(error);
    }
    if fork_opaque(
        scope
            .as_ref()
            .get_ref()
            .resource()
            .unwrap()
            .as_ref()
            .unwrap(),
    ) {
        unsafe { scope.as_mut().allow_fork_opaque() };
    }
    drop(native);
    let result = operation(scope.as_mut().resource_mut().unwrap().as_mut().unwrap());
    {
        let _native = defer_native_delivery();
        unsafe { scope.as_mut().retire() };
    }
    // Only a Copy result remains. Callers may now check cancellation without
    // hiding a successful prefix or leaving an FD lease/allocation behind.
    result
}
