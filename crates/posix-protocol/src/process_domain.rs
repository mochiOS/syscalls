//! Explicit userspace launch domains, independent of mutable POSIX parent/SID.
//! Create/contains payloads are empty; spawn carries POSIX credentials.
//! All object authority arrives as native attachments, never PID selectors.
pub const OP_CREATE: u16 = 141;
pub const OP_CONTAINS: u16 = 142;
/// Spawn credentials; domain TRANSFER and fresh child WAIT|SIGNAL attachments.
pub const OP_SPAWN: u16 = 143;
pub const TOKEN_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER;
pub const ATTACH_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_TRANSFER;
pub const PROCESS_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_WAIT;
pub const MAX_ROOTS: usize = 4;

pub fn decode_membership(input: &[u8]) -> Result<bool, crate::ProtocolError> {
    match input {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(crate::ProtocolError::InvalidLength),
    }
}
