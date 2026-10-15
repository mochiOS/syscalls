//! Native VM operations with caller-supplied, per-operation bounds.
use super::{SysResult, SyscallNumber, call2};
pub use mnu_abi::memory_map::Request;

pub fn map_bounded(request: Request) -> SysResult<u64> {
    let bytes = request.encode();
    call2(
        SyscallNumber::MemoryMapBounded,
        bytes.as_ptr() as u64,
        bytes.len() as u64,
    )
}
