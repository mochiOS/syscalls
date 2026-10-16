#![no_std]

#[cfg(test)]
extern crate std;

use core::arch::asm;
pub mod execution;
pub mod memory;
pub mod image;
pub use mnu_abi::status::Error as NativeError;

pub use mnu_abi::{
    ProcessorInfo,
    AddressWaitGuard, HandleInfo, HandleWaitGuard,
    ExecutionIdentity,
    ProcessExecutionUsage,
    ADDRESS_WAIT_INFINITE, AddressWaitResult, ClockId, ClockInstant, EACCES, EAGAIN, EBADF,
    EEXIST, EFAULT, EINVAL, EIO, EMFILE, EMSGSIZE, ENODATA, ENOENT, ENOMEM, ENOSPC, ENOSYS,
    ENOTSUP, ENXIO, EOVERFLOW, EPERM, EPIPE, ERANGE, ESRCH,
    HANDLE_OPTION_NONBLOCKING, HANDLE_OPTIONS_ALL, HANDLE_RIGHT_ALL,
    HANDLE_RIGHT_CONTROL, HANDLE_RIGHT_DUPLICATE, HANDLE_RIGHT_MAP, HANDLE_RIGHT_READ,
    HANDLE_RIGHT_RECEIVE, HANDLE_RIGHT_SEEK, HANDLE_RIGHT_SEND, HANDLE_RIGHT_SIGNAL,
    HANDLE_RIGHT_TRANSFER, HANDLE_RIGHT_WAIT, HANDLE_RIGHT_WRITE, HANDLE_SEEK_CURRENT,
    HANDLE_SEEK_END, HANDLE_SEEK_START, HANDLE_SIGNAL_IDLE, HANDLE_SIGNAL_PEER_CLOSED, HANDLE_SIGNAL_READABLE,
    HANDLE_SIGNAL_TERMINATED, HANDLE_SIGNAL_WRITABLE, HANDLE_WAIT_INFINITE,
    HANDLE_WAIT_MANY_MAX_ITEMS, HANDLE_WAIT_POLL, HandleWaitItem, IPC_MAX_OBJECT_HANDLES,
    IpcObjectHandle, IpcObjectHandles, PROCESS_INFO_RECORD_SIZE, PROCESS_STATE_EXITED, PROCESS_STATE_RUNNING,
    PROCESS_WAIT_INFINITE, PROCESS_WAIT_POLL, ProcessStatus, SUCCESS, StreamPair, SyscallNumber,
    ThreadCreateContext, ThreadInitialRegisters, ThreadSecurityContext, ThreadStatus, ThreadUpcallConfig,
    MEMORY_ACCESS_ALL, MEMORY_ACCESS_EXECUTE, MEMORY_ACCESS_READ, MEMORY_ACCESS_WRITE,
    MEMORY_MAP_EXACT, MEMORY_MAP_OPTIONS_ALL, MEMORY_MAP_SHARED,
    MEMORY_OBJECT_RESIZABLE,
    THREAD_UPCALL_EXCEPTIONS, THREAD_UPCALL_KIND_INTERRUPT, THREAD_UPCALL_KIND_EXCEPTION,
    MemoryFaultCause,
    ThreadUpcallSnapshot,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SysError {
    raw: i64,
}

pub type SysResult<T> = Result<T, SysError>;

impl SysError {
    pub const fn from_raw(raw: i64) -> Self {
        Self { raw }
    }

    pub const fn raw(self) -> i64 {
        self.raw
    }

    pub const fn native_error(self) -> Option<NativeError> {
        NativeError::from_raw(self.raw as u64)
    }

    /// Legacy status magnitude, not a C errno conversion. Tagged native
    /// failures have no errno here; use `native_error` or the compatibility
    /// layer's explicit mapping instead.
    pub fn errno(self) -> Option<u64> {
        if (-4095..=-1).contains(&self.raw) {
            Some(self.raw.unsigned_abs())
        } else {
            None
        }
    }
}

impl From<u64> for SysError {
    fn from(raw: u64) -> Self {
        Self { raw: raw as i64 }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawSyscallResult {
    raw: u64,
}

impl RawSyscallResult {
    pub const fn new(raw: u64) -> Self {
        Self { raw }
    }

    pub const fn raw(self) -> u64 {
        self.raw
    }

    pub fn into_result(self) -> SysResult<u64> {
        let signed = self.raw as i64;
        // Do not confuse high-bit Handle rights with failures. The tagged
        // native domain is separate from the legacy errno range, retained
        // only until the remaining mechanisms have migrated.
        if mnu_abi::status::is_error(self.raw) || (-4095..=-1).contains(&signed) {
            Err(SysError::from_raw(signed))
        } else {
            Ok(self.raw)
        }
    }
}

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

#[inline(always)]
pub fn raw_syscall0(number: SyscallNumber) -> RawSyscallResult {
    RawSyscallResult::new(unsafe { syscall0(number as u64) })
}

#[inline(always)]
pub fn raw_syscall1(number: SyscallNumber, arg0: u64) -> RawSyscallResult {
    RawSyscallResult::new(unsafe { syscall1(number as u64, arg0) })
}

#[inline(always)]
pub fn raw_syscall2(number: SyscallNumber, arg0: u64, arg1: u64) -> RawSyscallResult {
    RawSyscallResult::new(unsafe { syscall2(number as u64, arg0, arg1) })
}

#[inline(always)]
pub fn raw_syscall3(number: SyscallNumber, arg0: u64, arg1: u64, arg2: u64) -> RawSyscallResult {
    RawSyscallResult::new(unsafe { syscall3(number as u64, arg0, arg1, arg2) })
}

#[inline(always)]
pub fn raw_syscall4(
    number: SyscallNumber,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> RawSyscallResult {
    RawSyscallResult::new(unsafe { syscall4(number as u64, arg0, arg1, arg2, arg3) })
}

#[inline(always)]
pub fn raw_syscall5(
    number: SyscallNumber,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
) -> RawSyscallResult {
    RawSyscallResult::new(unsafe { syscall5(number as u64, arg0, arg1, arg2, arg3, arg4) })
}

#[inline(always)]
pub fn raw_syscall6(
    number: SyscallNumber,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> RawSyscallResult {
    RawSyscallResult::new(unsafe { syscall6(number as u64, arg0, arg1, arg2, arg3, arg4, arg5) })
}

#[inline(always)]
pub fn call0(number: SyscallNumber) -> SysResult<u64> {
    raw_syscall0(number).into_result()
}

#[inline(always)]
pub fn call1(number: SyscallNumber, arg0: u64) -> SysResult<u64> {
    raw_syscall1(number, arg0).into_result()
}

#[inline(always)]
pub fn call2(number: SyscallNumber, arg0: u64, arg1: u64) -> SysResult<u64> {
    raw_syscall2(number, arg0, arg1).into_result()
}

#[inline(always)]
pub fn call3(number: SyscallNumber, arg0: u64, arg1: u64, arg2: u64) -> SysResult<u64> {
    raw_syscall3(number, arg0, arg1, arg2).into_result()
}

#[inline(always)]
pub fn call4(number: SyscallNumber, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> SysResult<u64> {
    raw_syscall4(number, arg0, arg1, arg2, arg3).into_result()
}

#[inline(always)]
pub fn call5(
    number: SyscallNumber,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
) -> SysResult<u64> {
    raw_syscall5(number, arg0, arg1, arg2, arg3, arg4).into_result()
}

#[inline(always)]
pub fn call6(
    number: SyscallNumber,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> SysResult<u64> {
    raw_syscall6(number, arg0, arg1, arg2, arg3, arg4, arg5).into_result()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_error_detection() {
        assert!(SysError::from_raw(-22).errno() == Some(22));
        assert!(
            RawSyscallResult::new((-12i64) as u64)
                .into_result()
                .is_err()
        );
        assert!(RawSyscallResult::new(0).into_result().is_ok());
        assert!(RawSyscallResult::new(7).into_result().is_ok());
    }
}
