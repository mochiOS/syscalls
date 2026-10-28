//! Explicitly delegated, immutable pathname authority for read-only loaders.
//! No PID, UID or process-local Handle selector is serialized as authority.
use crate::{OpenAtRequest, OpenBase, ProtocolError};

pub const OP_CREATE: u16 = 136;
pub const OP_INFO: u16 = 137;
pub const OP_OPEN: u16 = 138;
/// Empty payload; scope TRANSFER, requester WAIT and child WAIT|SIGNAL.
pub const OP_REGISTER_CHILD: u16 = 139;
pub const TOKEN_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER;
pub const ATTACH_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_TRANSFER;
pub const FILE_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_READ | TOKEN_RIGHTS;

/// Reuse the pathname wire format, while excluding mutation, execution and
/// caller-selected directory attachments. Nonblocking prevents a FIFO open
/// from suspending the serialized control service.
pub fn decode_open(input: &[u8]) -> Result<OpenAtRequest<'_>, ProtocolError> {
    let request = crate::decode_open_at(input)?;
    if request.base == OpenBase::AttachedDirectory
        || request.options != (crate::OPEN_READ | crate::OPEN_NONBLOCK)
        || request.mode != 0
    {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(request)
}
