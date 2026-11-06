//! Authenticate captured code for loading into the caller's existing domain.
//! Exactly one READ | MAP native RAM object accompanies this request. Success
//! returns its full-file SHA-256, never an execution permit or new authority.
use super::ProtocolError;

pub const VERIFY_OPCODE: u32 = 0x4341_4c49;
pub const VERSION: u32 = 1;
pub const REQUEST_LEN: usize = 24;
pub const REPLY_LEN: usize = 40;

pub fn encode(length: u64, output: &mut [u8]) -> Result<usize, ProtocolError> {
    if length == 0 {
        return Err(ProtocolError::InvalidField);
    }
    let bytes = output
        .get_mut(..REQUEST_LEN)
        .ok_or(ProtocolError::InvalidLength)?;
    bytes.fill(0);
    bytes[..4].copy_from_slice(&VERIFY_OPCODE.to_le_bytes());
    bytes[4..8].copy_from_slice(&VERSION.to_le_bytes());
    bytes[8..16].copy_from_slice(&length.to_le_bytes());
    Ok(REQUEST_LEN)
}

pub fn decode(bytes: &[u8]) -> Result<u64, ProtocolError> {
    if bytes.len() != REQUEST_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    if u32::from_le_bytes(bytes[..4].try_into().unwrap()) != VERIFY_OPCODE {
        return Err(ProtocolError::UnknownOpcode);
    }
    if u32::from_le_bytes(bytes[4..8].try_into().unwrap()) != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let length = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    if length == 0 || bytes[16..] != [0; 8] {
        return Err(ProtocolError::InvalidField);
    }
    Ok(length)
}

pub fn reply(status: u64, digest: Option<&[u8; 32]>) -> [u8; REPLY_LEN] {
    let mut bytes = [0; REPLY_LEN];
    bytes[..8].copy_from_slice(&status.to_le_bytes());
    if status == 0 {
        if let Some(digest) = digest {
            bytes[8..].copy_from_slice(digest);
        }
    }
    bytes
}

pub fn decode_reply(bytes: &[u8]) -> Result<(u64, &[u8; 32]), ProtocolError> {
    if bytes.len() != REPLY_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let status = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    if status != 0 && bytes[8..] != [0; 32] {
        return Err(ProtocolError::InvalidField);
    }
    Ok((status, bytes[8..].try_into().unwrap()))
}
