//! Native image replacement with a caller-supplied virtual-byte ceiling.
use super::{SysError, SysResult, SyscallNumber};
use core::convert::Infallible;

/// Success enters the new image and never returns. No path lookup, startup
/// convention or resource-limit policy is supplied by this wrapper.
pub fn replace_bounded(
    image_handle: u32,
    identity: &str,
    startup: &[u8],
    byte_ceiling: u64,
) -> SysResult<Infallible> {
    super::call6(
        SyscallNumber::ProcessImageReplaceBounded,
        u64::from(image_handle),
        identity.as_ptr() as u64,
        identity.len() as u64,
        startup.as_ptr() as u64,
        startup.len() as u64,
        byte_ceiling,
    )?;
    // A native success value must not turn a failed replacement into a
    // returning "successful exec" at the language boundary.
    Err(SysError::from_raw(mnu_abi::EIO as i64))
}
