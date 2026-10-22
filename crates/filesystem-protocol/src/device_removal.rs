//! Conditional owner cleanup. Identity is only a comparison precondition;
//! authority still comes from an explicitly attached CONTROL|TRANSFER parent.
use crate::ProtocolError;

pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub device: u64,
    pub node_id: u64,
    pub name: &'a [u8],
}

fn valid(request: Request<'_>) -> bool {
    request.node_id != 0
        && !request.name.is_empty()
        && request.name.len() <= crate::device_namespace::MAX_NAME_LEN
        && request.name != b"."
        && request.name != b".."
        && !request.name.contains(&0)
        && !request.name.contains(&b'/')
}

pub fn encode(request: Request<'_>, output: &mut [u8]) -> Result<usize, ProtocolError> {
    if !valid(request) {
        return Err(ProtocolError::InvalidLength);
    }
    let length = HEADER_LEN + request.name.len();
    if output.len() < length {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..length].fill(0);
    output[..2].copy_from_slice(&VERSION.to_le_bytes());
    output[8..16].copy_from_slice(&request.device.to_le_bytes());
    output[16..24].copy_from_slice(&request.node_id.to_le_bytes());
    output[24..26].copy_from_slice(&(request.name.len() as u16).to_le_bytes());
    output[HEADER_LEN..length].copy_from_slice(request.name);
    Ok(length)
}

pub fn decode(input: &[u8]) -> Result<Request<'_>, ProtocolError> {
    let header = input
        .get(..HEADER_LEN)
        .ok_or(ProtocolError::InvalidLength)?;
    if header[..2] != VERSION.to_le_bytes() {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let length = usize::from(u16::from_le_bytes(header[24..26].try_into().unwrap()));
    if input.len() != HEADER_LEN + length
        || header[2..8].iter().any(|b| *b != 0)
        || header[26..].iter().any(|b| *b != 0)
    {
        return Err(ProtocolError::InvalidLength);
    }
    let request = Request {
        device: u64::from_le_bytes(header[8..16].try_into().unwrap()),
        node_id: u64::from_le_bytes(header[16..24].try_into().unwrap()),
        name: &input[HEADER_LEN..],
    };
    if !valid(request) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(request)
}
