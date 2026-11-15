//! x86-64 native syscall register convention.
use core::arch::asm;

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn syscall0(number: u64) -> u64 {
    let ret: u64;
    asm!(
    "syscall",
    inlateout("rax") number => ret,
    lateout("rcx") _,
    lateout("r11") _,
    clobber_abi("C"),
    options(nostack)
    );
    ret
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn syscall1(number: u64, arg0: u64) -> u64 {
    let ret: u64;
    asm!(
    "syscall",
    inlateout("rax") number => ret,
    in("rdi") arg0,
    lateout("rcx") _,
    lateout("r11") _,
    clobber_abi("C"),
    options(nostack)
    );
    ret
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn syscall2(number: u64, arg0: u64, arg1: u64) -> u64 {
    let ret: u64;
    asm!(
    "syscall",
    inlateout("rax") number => ret,
    in("rdi") arg0,
    in("rsi") arg1,
    lateout("rcx") _,
    lateout("r11") _,
    clobber_abi("C"),
    options(nostack)
    );
    ret
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> u64 {
    let ret: u64;
    asm!(
    "syscall",
    inlateout("rax") number => ret,
    in("rdi") arg0,
    in("rsi") arg1,
    in("rdx") arg2,
    lateout("rcx") _,
    lateout("r11") _,
    clobber_abi("C"),
    options(nostack)
    );
    ret
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn syscall4(number: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> u64 {
    let ret: u64;
    asm!(
    "syscall",
    inlateout("rax") number => ret,
    in("rdi") arg0,
    in("rsi") arg1,
    in("rdx") arg2,
    inlateout("r10") arg3 => _,
    lateout("rcx") _,
    lateout("r11") _,
    clobber_abi("C"),
    options(nostack)
    );
    ret
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn syscall5(number: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64) -> u64 {
    let ret: u64;
    asm!(
    "syscall",
    inlateout("rax") number => ret,
    in("rdi") arg0,
    in("rsi") arg1,
    in("rdx") arg2,
    inlateout("r10") arg3 => _,
    in("r8") arg4,
    lateout("rcx") _,
    lateout("r11") _,
    clobber_abi("C"),
    options(nostack)
    );
    ret
}

#[inline(always)]
#[allow(unsafe_op_in_unsafe_fn)]
pub unsafe fn syscall6(
    number: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> u64 {
    let ret: u64;
    asm!(
    "syscall",
    inlateout("rax") number => ret,
    in("rdi") arg0,
    in("rsi") arg1,
    in("rdx") arg2,
    inlateout("r10") arg3 => _,
    in("r8") arg4,
    in("r9") arg5,
    lateout("rcx") _,
    lateout("r11") _,
    clobber_abi("C"),
    options(nostack)
    );
    ret
}
