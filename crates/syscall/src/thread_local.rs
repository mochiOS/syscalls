//! Native current-thread local-base register, independent of any TLS ABI.
use super::{SysError, SysResult, SyscallNumber};
use mnu_abi::status::Error;

pub fn set_base(base: u64) -> SysResult<()> {
    let result = super::call2(SyscallNumber::ThreadLocalBaseSet, base, 0)?;
    if result != mnu_abi::SUCCESS {
        return Err(SysError::from_raw(Error::BackingFailure.into_raw() as i64));
    }
    Ok(())
}
