//! Native caller identification without credentials or service discovery.

use super::{ExecutionIdentity, SysError, SysResult, SyscallNumber};

pub fn identity() -> SysResult<ExecutionIdentity> {
    let mut identity = ExecutionIdentity::default();
    let status = super::call2(
        SyscallNumber::ExecutionIdentityRead,
        (&mut identity as *mut ExecutionIdentity) as u64,
        core::mem::size_of::<ExecutionIdentity>() as u64,
    )?;
    if status != mnu_abi::SUCCESS || identity.process_id == 0 || identity.thread_id == 0 {
        return Err(SysError::from_raw(mnu_abi::EIO as i64));
    }
    Ok(identity)
}
