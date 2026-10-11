//! User-space return continuation for an explicitly created VM clone.

use mnu_abi::ThreadCreateContext;

// The assembly is deliberately tied to the explicit native wire layout.
const _: () = {
    assert!(core::mem::size_of::<ThreadCreateContext>() == 176);
    assert!(core::mem::offset_of!(ThreadCreateContext, entry) == 0);
    assert!(core::mem::offset_of!(ThreadCreateContext, stack_pointer) == 8);
    assert!(core::mem::offset_of!(ThreadCreateContext, argument) == 16);
    assert!(core::mem::offset_of!(ThreadCreateContext, thread_local_base) == 24);
    assert!(core::mem::offset_of!(ThreadCreateContext, flags) == 32);
    assert!(core::mem::offset_of!(ThreadCreateContext, reserved) == 40);
    assert!(core::mem::offset_of!(ThreadCreateContext, registers) == 64);
};

core::arch::global_asm!(include_str!("snapshot_x86_64.S"));

unsafe extern "C" {
    fn mochios_posix_capture_snapshot(
        context: *mut ThreadCreateContext,
        thread_local_base: u64,
        capture: unsafe extern "C" fn() -> u64,
    ) -> u64;
}

/// Captures a continuation before calling an address-space snapshot backend.
/// The parent receives the backend's raw result; a process created with the
/// saved context returns zero from this same invocation in its cloned stack.
///
/// TLS is an explicit runtime-provided value, not inferred from FS memory or
/// obtained using an architecture-specific POSIX syscall. The child inherits
/// the C ABI callee-saved registers and return address captured by assembly.
///
/// # Safety
/// `capture` must snapshot the current address space without modifying the
/// captured caller frame or violating the C ABI. A child may resume this
/// context only in that matching snapshot, with the same TLS layout and native
/// Handle references. No other thread may mutate the caller's runtime state
/// during capture. This is a returns-twice operation: parent-only cleanup must
/// not run in the child, and any copied locks must be released in both paths.
pub unsafe fn capture_with(
    context: &mut ThreadCreateContext,
    thread_local_base: u64,
    capture: unsafe extern "C" fn() -> u64,
) -> u64 {
    unsafe { mochios_posix_capture_snapshot(context, thread_local_base, capture) }
}

/// Native AddressSpaceClone backend. It creates no process and copies no
/// execution authority; the caller must separately authorize ProcessCreate.
///
/// # Safety
/// The same requirements as [`capture_with`] apply. Preserve the raw result:
/// zero denotes the resumed child, positive values the parent's VM Handle,
/// and native error values are interpreted only on the parent path.
#[cfg(feature = "syscall-endpoint")]
pub unsafe fn capture_native(context: &mut ThreadCreateContext, thread_local_base: u64) -> u64 {
    unsafe extern "C" fn clone_current() -> u64 {
        mochi_user_syscall::raw_syscall0(mochi_user_syscall::SyscallNumber::AddressSpaceClone)
            .raw()
    }
    unsafe { capture_with(context, thread_local_base, clone_current) }
}
