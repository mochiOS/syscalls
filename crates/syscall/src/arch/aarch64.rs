//! AArch64 native entry: SVC #0, number in x8, arguments in x0..x5.
//! Uses the Linux AArch64 register convention, without changing syscall meanings.
use core::arch::asm;

/// # Safety
/// The caller must satisfy the selected native syscall's argument, pointer and
/// lifetime requirements. This is a mochiOS entry, not a host POSIX call.
#[inline(always)]
pub unsafe fn syscall6(
    number: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> u64 {
    let result;
    unsafe {
        asm!("svc #0", in("x8") number,
            inlateout("x0") arg0 => result,
            in("x1") arg1, in("x2") arg2, in("x3") arg3,
            in("x4") arg4, in("x5") arg5,
            clobber_abi("C"), options(nostack));
    }
    result
}

/// # Safety
/// The caller must satisfy the selected native syscall's argument requirements.
#[inline(always)]
pub unsafe fn syscall0(number: u64) -> u64 {
    unsafe { syscall6(number, 0, 0, 0, 0, 0, 0) }
}

/// # Safety
/// The caller must satisfy the selected native syscall's argument requirements.
#[inline(always)]
pub unsafe fn syscall1(number: u64, arg0: u64) -> u64 {
    unsafe { syscall6(number, arg0, 0, 0, 0, 0, 0) }
}

/// # Safety
/// The caller must satisfy the selected native syscall's argument requirements.
#[inline(always)]
pub unsafe fn syscall2(number: u64, arg0: u64, arg1: u64) -> u64 {
    unsafe { syscall6(number, arg0, arg1, 0, 0, 0, 0) }
}

/// # Safety
/// The caller must satisfy the selected native syscall's argument requirements.
#[inline(always)]
pub unsafe fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> u64 {
    unsafe { syscall6(number, arg0, arg1, arg2, 0, 0, 0) }
}

/// # Safety
/// The caller must satisfy the selected native syscall's argument requirements.
#[inline(always)]
pub unsafe fn syscall4(number: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    unsafe { syscall6(number, arg0, arg1, arg2, arg3, 0, 0) }
}

/// # Safety
/// The caller must satisfy the selected native syscall's argument requirements.
#[inline(always)]
pub unsafe fn syscall5(number: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    unsafe { syscall6(number, arg0, arg1, arg2, arg3, arg4, 0) }
}
