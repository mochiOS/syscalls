//! Scoped CPU continuation for synchronous userspace signal dispatch.
//!
//! Asynchronous upcalls use the kernel's interrupted snapshot instead. This
//! captures a real C call boundary, without inventing an interrupted PC or
//! asking the kernel to interpret POSIX state.
use crate::signal_context::*;
use core::ffi::c_void;

#[cfg(target_arch = "x86_64")]
const _: () = {
    assert!(core::mem::size_of::<MachineContext>() == 656);
    assert!(core::mem::align_of::<MachineContext>() == 16);
    assert!(core::mem::offset_of!(MachineContext, gregs) == 0);
    assert!(core::mem::offset_of!(MachineContext, fpregs) == 144);
    assert!(REG_R8 == 0 && REG_R9 == 1 && REG_R10 == 2 && REG_R11 == 3);
    assert!(REG_R12 == 4 && REG_R13 == 5 && REG_R14 == 6 && REG_R15 == 7);
    assert!(REG_RDI == 8 && REG_RSI == 9 && REG_RBP == 10 && REG_RBX == 11);
    assert!(REG_RDX == 12 && REG_RAX == 13 && REG_RCX == 14);
    assert!(REG_RSP == 15 && REG_RIP == 16 && REG_EFL == 17 && NGREG == 18);
};

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("signal_checkpoint_x86_64.S"));
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(include_str!("signal_checkpoint_aarch64.S"));
#[cfg(target_arch = "aarch64")]
const _: () = {
    assert!(core::mem::size_of::<MachineContext>() == 800);
    assert!(core::mem::offset_of!(MachineContext, fpregs) == 272);
    assert!(core::mem::offset_of!(MachineContext, fpcr) == 784);
    assert!(core::mem::offset_of!(MachineContext, fpsr) == 792);
};

unsafe extern "C" {
    fn mochios_posix_signal_checkpoint(
        callback: unsafe extern "C" fn(*mut MachineContext, *mut c_void),
        argument: *mut c_void,
    ) -> u64;
}

/// Runs `callback` with a stack-owned CPU continuation, then resumes it.
/// The result register initially contains zero; its selected value
/// becomes this call's result. GPRs, flags and base FP/SIMD state are restored
/// from the continuation after the callback returns. On AArch64 IP0 (x16)
/// holds the final branch target, as allowed at this C call boundary; all
/// callee-saved registers and the complete FP/SIMD image are restored.
/// Native asynchronous upcall return restores x16 as well. TLS is not changed.
///
/// # Safety
/// The callback must return normally, never retain the context pointer, and
/// supply valid CPU state. Changing the continuation must respect the caller's
/// live stack, register assumptions and C ABI. In particular, the selected
/// stack must allow any ABI return storage (a PC/flags pair below RSP on x86).
/// This is a synchronous
/// call boundary, not a red-zone-safe asynchronous signal-return mechanism.
/// POSIX mask/stack bookkeeping and handler-token completion must finish in
/// the callback before a changed continuation takes effect.
pub unsafe fn run_with(
    callback: unsafe extern "C" fn(*mut MachineContext, *mut c_void),
    argument: *mut c_void,
) -> u64 {
    unsafe { mochios_posix_signal_checkpoint(callback, argument) }
}
