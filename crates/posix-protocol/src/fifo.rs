//! Userspace FIFO open continuation. A pending reply owns an already registered
//! data description plus one notification; it is not a pathname replay ticket.
use crate::{OPEN_READ, OPEN_WRITE};
pub const WAIT_MAGIC: &[u8; 4] = b"FIWT";
pub const WAIT_LEN: usize = 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitCondition {
    Open,
    Read,
    Write(usize),
}
impl WaitCondition {
    pub fn encode(self) -> Result<[u8; WAIT_LEN], crate::ProtocolError> {
        let (kind, length) = match self {
            Self::Open => (0u16, 0),
            Self::Read => (1, 0),
            Self::Write(0) => return Err(crate::ProtocolError::InvalidLength),
            Self::Write(length) => (
                2,
                u64::try_from(length).map_err(|_| crate::ProtocolError::InvalidLength)?,
            ),
        };
        let mut bytes = [0; WAIT_LEN];
        bytes[..4].copy_from_slice(WAIT_MAGIC);
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&kind.to_le_bytes());
        bytes[8..].copy_from_slice(&length.to_le_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, crate::ProtocolError> {
        if bytes.len() != WAIT_LEN || &bytes[..4] != WAIT_MAGIC || bytes[4..6] != 1u16.to_le_bytes()
        {
            return Err(crate::ProtocolError::InvalidLength);
        }
        let kind = u16::from_le_bytes([bytes[6], bytes[7]]);
        let length = u64::from_le_bytes(
            bytes[8..]
                .try_into()
                .map_err(|_| crate::ProtocolError::InvalidLength)?,
        );
        match (kind, length) {
            (0, 0) => Ok(Self::Open),
            (1, 0) => Ok(Self::Read),
            (2, 1..) => Ok(Self::Write(
                usize::try_from(length).map_err(|_| crate::ProtocolError::InvalidLength)?,
            )),
            _ => Err(crate::ProtocolError::InvalidLength),
        }
    }
    pub fn source_direction(self, rights: u64) -> Option<u64> {
        let direction = rights & (mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WRITE);
        let valid = match self {
            Self::Open => {
                direction == mnu_abi::HANDLE_RIGHT_READ || direction == mnu_abi::HANDLE_RIGHT_WRITE
            }
            Self::Read => direction == mnu_abi::HANDLE_RIGHT_READ,
            Self::Write(_) => direction == mnu_abi::HANDLE_RIGHT_WRITE,
        };
        valid.then_some(direction)
    }
}
pub const COMMON_DATA_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_CONTROL
    | mnu_abi::HANDLE_RIGHT_DUPLICATE
    | mnu_abi::HANDLE_RIGHT_TRANSFER
    | mnu_abi::HANDLE_RIGHT_WAIT;
pub const NOTIFICATION_RIGHTS: u64 =
    mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER;
/// Only OPEN_AT with queued admission may opt in to the two-Handle reply.
pub const OPEN_CONTINUATION: u32 = 1 << 29;
/// OP_STATUS success, empty body, exactly [data, notification] attachments.
/// Await the one-shot notification outside service/runtime locks, then use
/// the same data Handle. Closing both references cancels the pending open.
pub const OPEN_PENDING_REPLY: u32 = 1;
pub fn data_rights(options: u32) -> Option<u64> {
    match options & (OPEN_READ | OPEN_WRITE) {
        OPEN_READ => Some(COMMON_DATA_RIGHTS | mnu_abi::HANDLE_RIGHT_READ),
        OPEN_WRITE => Some(COMMON_DATA_RIGHTS | mnu_abi::HANDLE_RIGHT_WRITE),
        _ => None,
    }
}
