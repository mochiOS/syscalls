//! Native fast path for process-local and shared-memory synchronization.

use core::sync::atomic::{AtomicU32, AtomicU64};

use mochi_user_syscall as syscall;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitStatus {
    Awoken,
    ValueChanged,
    DeadlineReached,
}

/// Waits while `address` still contains `expected`.
///
/// `deadline_nanoseconds` is an absolute native monotonic-clock deadline, or
/// `ADDRESS_WAIT_INFINITE`. POSIX timeout and errno conversion remain above
/// this native fast path.
pub fn wait_u32(
    address: &AtomicU32,
    expected: u32,
    deadline_nanoseconds: u64,
) -> Result<WaitStatus, syscall::SysError> {
    let raw = syscall::call4(
        syscall::SyscallNumber::WaitOnAddress,
        address as *const AtomicU32 as u64,
        u64::from(expected),
        core::mem::size_of::<u32>() as u64,
        deadline_nanoseconds,
    )?;
    match syscall::AddressWaitResult::from_raw(raw) {
        Some(syscall::AddressWaitResult::Awoken) => Ok(WaitStatus::Awoken),
        Some(syscall::AddressWaitResult::ValueChanged) => Ok(WaitStatus::ValueChanged),
        Some(syscall::AddressWaitResult::DeadlineReached) => Ok(WaitStatus::DeadlineReached),
        None => Err(syscall::SysError::from_raw(syscall::EIO as i64)),
    }
}

/// Wakes up to `maximum_count` waiters for `address`.
pub fn wake_u32(address: &AtomicU32, maximum_count: usize) -> Result<usize, syscall::SysError> {
    wake_address(address as *const AtomicU32 as u64, maximum_count)
}

/// Wakes address and guarded-object waiters subscribed to a 64-bit counter.
pub fn wake_u64(address: &AtomicU64, maximum_count: usize) -> Result<usize, syscall::SysError> {
    wake_address(address as *const AtomicU64 as u64, maximum_count)
}

fn wake_address(address: u64, maximum_count: usize) -> Result<usize, syscall::SysError> {
    let raw = syscall::call2(
        syscall::SyscallNumber::WakeAddress,
        address,
        maximum_count as u64,
    )?;
    usize::try_from(raw).map_err(|_| syscall::SysError::from_raw(syscall::EOVERFLOW as i64))
}
