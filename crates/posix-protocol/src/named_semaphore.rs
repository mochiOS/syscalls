//! Serialized names/options only. Backing references travel as IPC attachments.

use super::{ProtocolError, get_u32, put_u32};

pub const MAX_NAME_BYTES: usize = 255;
pub const OPEN_HEADER_LEN: usize = 16;
pub const NAME_HEADER_LEN: usize = 4;
pub const CREATE: u32 = 1;
pub const EXCLUSIVE: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Open<'a> {
    pub options: u32,
    pub mode: u32,
    pub value: u32,
    pub name: &'a [u8],
}

fn valid_name(name: &[u8]) -> bool {
    name.first() == Some(&b'/')
        && (2..=MAX_NAME_BYTES + 1).contains(&name.len())
        && !name[1..].iter().any(|byte| matches!(byte, b'/' | 0))
}

fn valid_open(request: Open<'_>) -> bool {
    valid_name(request.name)
        && request.options & !(CREATE | EXCLUSIVE) == 0
        && (request.options & CREATE != 0
            || (request.options == 0 && request.mode == 0 && request.value == 0))
}

pub fn encode_open(request: Open<'_>, output: &mut [u8]) -> Result<usize, ProtocolError> {
    if !valid_open(request) {
        return Err(ProtocolError::InvalidLength);
    }
    let length = OPEN_HEADER_LEN + request.name.len();
    if output.len() < length {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, request.options);
    put_u32(output, 4, request.mode);
    put_u32(output, 8, request.value);
    put_u32(output, 12, request.name.len() as u32);
    output[OPEN_HEADER_LEN..length].copy_from_slice(request.name);
    Ok(length)
}

pub fn decode_open(input: &[u8]) -> Result<Open<'_>, ProtocolError> {
    if input.len() < OPEN_HEADER_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let request = Open {
        options: get_u32(input, 0),
        mode: get_u32(input, 4),
        value: get_u32(input, 8),
        name: &input[OPEN_HEADER_LEN..],
    };
    if get_u32(input, 12) as usize != request.name.len() || !valid_open(request) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(request)
}

pub fn encode_name(name: &[u8], output: &mut [u8]) -> Result<usize, ProtocolError> {
    if !valid_name(name) {
        return Err(ProtocolError::InvalidLength);
    }
    let length = NAME_HEADER_LEN + name.len();
    if output.len() < length {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, name.len() as u32);
    output[NAME_HEADER_LEN..length].copy_from_slice(name);
    Ok(length)
}

pub fn decode_name(input: &[u8]) -> Result<&[u8], ProtocolError> {
    if input.len() < NAME_HEADER_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let name = &input[NAME_HEADER_LEN..];
    if get_u32(input, 0) as usize != name.len() || !valid_name(name) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(name)
}
