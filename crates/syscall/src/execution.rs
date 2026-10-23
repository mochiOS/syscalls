//! Native caller identification without credentials or service discovery.

use super::{ExecutionIdentity, ProcessExecutionUsage, SysError, SysResult, SyscallNumber};
use mnu_abi::status::Error;

/// Observe only the caller (None) or an explicit WAIT-capable Process Handle.
pub fn usage(handle: Option<u32>) -> SysResult<ProcessExecutionUsage> {
    let raw = match handle {
        None => 0,
        Some(0) => return Err(SysError::from_raw(Error::InvalidArgument.into_raw() as i64)),
        Some(handle) => handle,
    };
    let mut usage = ProcessExecutionUsage::default();
    let status = super::call3(
        SyscallNumber::ProcessExecutionRead,
        u64::from(raw),
        (&mut usage as *mut ProcessExecutionUsage) as u64,
        core::mem::size_of::<ProcessExecutionUsage>() as u64,
    )?;
    if status != mnu_abi::SUCCESS || usage.ticks_per_second == 0 || usage.reserved != 0 {
        return Err(SysError::from_raw(Error::BackingFailure.into_raw() as i64));
    }
    Ok(usage)
}

pub fn identity() -> SysResult<ExecutionIdentity> {
    let mut identity = ExecutionIdentity::default();
    let status = super::call2(
        SyscallNumber::ExecutionIdentityRead,
        (&mut identity as *mut ExecutionIdentity) as u64,
        core::mem::size_of::<ExecutionIdentity>() as u64,
    )?;
    if status != mnu_abi::SUCCESS || identity.process_id == 0 || identity.thread_id == 0 {
        return Err(SysError::from_raw(Error::BackingFailure.into_raw() as i64));
    }
    Ok(identity)
}

/// Inspect a native IPC endpoint without importing POSIX or package policy.
pub fn endpoint_identity(endpoint: u64) -> SysResult<ExecutionIdentity> {
    if endpoint == 0 {
        return Err(SysError::from_raw(Error::InvalidArgument.into_raw() as i64));
    }
    let mut identity = ExecutionIdentity::default();
    let status = super::call3(
        SyscallNumber::IpcEndpointIdentityRead,
        (&mut identity as *mut ExecutionIdentity) as u64,
        core::mem::size_of::<ExecutionIdentity>() as u64,
        endpoint,
    )?;
    if status != mnu_abi::SUCCESS || identity.process_id == 0 || identity.thread_id == 0 {
        return Err(SysError::from_raw(Error::BackingFailure.into_raw() as i64));
    }
    Ok(identity)
}

/// Sample CPU time through an explicit WAIT-capable Thread Handle. Zero is
/// never a caller/TID shorthand; native selectors grant all observation rights.
pub fn thread_clock(handle: u32) -> SysResult<super::ClockInstant> {
    if handle == 0 {
        return Err(SysError::from_raw(Error::InvalidArgument.into_raw() as i64));
    }
    let mut instant = super::ClockInstant::default();
    let status = super::call3(
        SyscallNumber::ThreadClockRead,
        u64::from(handle),
        (&mut instant as *mut super::ClockInstant) as u64,
        core::mem::size_of::<super::ClockInstant>() as u64,
    )?;
    if status != mnu_abi::SUCCESS || instant.reserved != 0 || instant.nanoseconds >= 1_000_000_000 {
        return Err(SysError::from_raw(Error::BackingFailure.into_raw() as i64));
    }
    Ok(instant)
}
