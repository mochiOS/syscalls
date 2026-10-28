//! Calls trusted linker-owned arrays after runtime setup. Application-provided
//! dynamic objects need separate validation and lifetime management.
use super::InitFn;

/// # Safety
/// The range must be a live array of valid callbacks owned by this image.
pub(super) unsafe fn initialize(start: *const InitFn, end: *const InitFn) {
    let mut current = start;
    while current < end {
        let function = unsafe { current.read() };
        unsafe { function() };
        current = unsafe { current.add(1) };
    }
}

/// Finalizers undo initialization in reverse array order. The runtime registers
/// this runner before application constructors, so later atexit callbacks run
/// first. Neither runner is part of the native ProcessExit mechanism.
///
/// # Safety
/// The range must be a live array of valid callbacks owned by this image.
pub(super) unsafe fn finalize(start: *const InitFn, end: *const InitFn) {
    let mut current = end;
    while current > start {
        current = unsafe { current.sub(1) };
        let function = unsafe { current.read() };
        unsafe { function() };
    }
}
