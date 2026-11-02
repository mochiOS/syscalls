//! Authenticated installed or signed standalone source replacement.
//! Exactly one READ | MAP RAM object accompanies the request through IPC.
//! No caller-supplied digest, PID, FD, signer trust or requested grants appear.
use super::{ProtocolError, validate_executable_identity};

pub const AUTHORIZE_OPCODE: u32 = 0x4341_5349;
/// Version 3 selects authenticated installed code before standalone signatures.
/// Earlier authorization policies are deliberately rejected.
pub const VERSION: u32 = 3;
pub const PREFIX_LEN: usize = 24;

#[derive(Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub source_length: u64,
    /// Verification key only, not a trusted developer assertion.
    pub public_key: Option<&'a [u8; 32]>,
    /// Opaque one-shot lookup key, not an application identity override.
    pub identity: &'a str,
}

pub fn encode(request: &Request<'_>, output: &mut [u8]) -> Result<usize, ProtocolError> {
    validate_executable_identity(request.identity)?;
    if request.source_length == 0 {
        return Err(ProtocolError::InvalidField);
    }
    let key_length = if request.public_key.is_some() { 32 } else { 0 };
    let length = PREFIX_LEN + key_length + request.identity.len();
    if output.len() < length {
        return Err(ProtocolError::InvalidLength);
    }
    output[..4].copy_from_slice(&AUTHORIZE_OPCODE.to_le_bytes());
    output[4..8].copy_from_slice(&VERSION.to_le_bytes());
    output[8..16].copy_from_slice(&request.source_length.to_le_bytes());
    output[16..20].copy_from_slice(&u32::from(request.public_key.is_some()).to_le_bytes());
    output[20..24].fill(0);
    if let Some(key) = request.public_key {
        output[PREFIX_LEN..PREFIX_LEN + 32].copy_from_slice(key);
    }
    output[PREFIX_LEN + key_length..length].copy_from_slice(request.identity.as_bytes());
    Ok(length)
}

pub fn decode(bytes: &[u8]) -> Result<Request<'_>, ProtocolError> {
    if bytes.len() < PREFIX_LEN {
        return Err(ProtocolError::TooShort);
    }
    if u32::from_le_bytes(bytes[..4].try_into().unwrap()) != AUTHORIZE_OPCODE {
        return Err(ProtocolError::UnknownOpcode);
    }
    if u32::from_le_bytes(bytes[4..8].try_into().unwrap()) != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let source_length = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    if source_length == 0 || bytes[20..24] != [0; 4] {
        return Err(ProtocolError::InvalidField);
    }
    let key_length = match u32::from_le_bytes(bytes[16..20].try_into().unwrap()) {
        0 => 0,
        1 => 32,
        _ => return Err(ProtocolError::InvalidField),
    };
    let tail = bytes
        .get(PREFIX_LEN + key_length..)
        .ok_or(ProtocolError::TooShort)?;
    let identity = core::str::from_utf8(tail).map_err(|_| ProtocolError::InvalidUtf8)?;
    validate_executable_identity(identity)?;
    let public_key = if key_length == 0 {
        None
    } else {
        Some(bytes[PREFIX_LEN..PREFIX_LEN + 32].try_into().unwrap())
    };
    Ok(Request {
        source_length,
        public_key,
        identity,
    })
}
