//! Explicitly delegated, immutable pathname authority for read-only loaders.
//! No PID, UID or process-local Handle selector is serialized as authority.
use crate::{OpenAtRequest, OpenBase, ProtocolError};

pub const OP_CREATE: u16 = 136;
pub const OP_INFO: u16 = 137;
pub const OP_OPEN: u16 = 138;
/// Empty payload; scope TRANSFER, requester WAIT and child WAIT|SIGNAL.
pub const OP_REGISTER_CHILD: u16 = 139;
/// Empty request and one scope. Authenticated source metadata, never a PID selector.
pub const OP_SOURCE_INFO: u16 = 140;
pub const SOURCE_INFO_LEN: usize = 8 + crate::SESSION_INFO_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceInfo {
    pub process_id: u64,
    pub session: crate::SessionInfo,
}
pub fn encode_source_info(info: SourceInfo, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() != SOURCE_INFO_LEN || info.process_id == 0 {
        return Err(ProtocolError::InvalidLength);
    }
    output[..8].copy_from_slice(&info.process_id.to_le_bytes());
    crate::encode_session_info(info.session, &mut output[8..])
}
pub fn decode_source_info(input: &[u8]) -> Result<SourceInfo, ProtocolError> {
    if input.len() != SOURCE_INFO_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let process_id = u64::from_le_bytes(input[..8].try_into().unwrap());
    if process_id == 0 {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(SourceInfo {
        process_id,
        session: crate::decode_session_info(&input[8..])?,
    })
}
pub const TOKEN_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER;
pub const ATTACH_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_TRANSFER;
pub const FILE_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_READ | TOKEN_RIGHTS;

/// Reuse the pathname wire format, while excluding mutation and
/// caller-selected directory attachments. Nonblocking prevents a FIFO open
/// from suspending the serialized control service.
pub fn decode_open(input: &[u8]) -> Result<OpenAtRequest<'_>, ProtocolError> {
    let request = crate::decode_open_at(input)?;
    if request.base == OpenBase::AttachedDirectory
        || !matches!(request.options,
            value if value == crate::OPEN_READ | crate::OPEN_NONBLOCK
                || value == crate::OPEN_READ | crate::OPEN_NONBLOCK | crate::OPEN_EXECUTE)
        || request.mode != 0
    {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(request)
}
