//! Conditional owner configuration. IDs are comparison preconditions only;
//! the explicitly attached parent Handle supplies all authority.
use crate::{ProtocolError, device_removal};

pub const VERSION: u16 = 1;
const ATTRIBUTES_LEN: usize = 16;
pub const HEADER_LEN: usize = ATTRIBUTES_LEN + device_removal::HEADER_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub identity: device_removal::Request<'a>,
}

pub fn encode(request: Request<'_>, output: &mut [u8]) -> Result<usize, ProtocolError> {
    if request.mode & !0o7777 != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    if output.len() < HEADER_LEN + request.identity.name.len() {
        return Err(ProtocolError::BufferTooSmall);
    }
    let length = device_removal::encode(request.identity, &mut output[ATTRIBUTES_LEN..])?;
    output[..ATTRIBUTES_LEN].fill(0);
    output[..2].copy_from_slice(&VERSION.to_le_bytes());
    output[2..4].copy_from_slice(&request.mode.to_le_bytes());
    output[4..8].copy_from_slice(&request.uid.to_le_bytes());
    output[8..12].copy_from_slice(&request.gid.to_le_bytes());
    Ok(ATTRIBUTES_LEN + length)
}

pub fn decode(input: &[u8]) -> Result<Request<'_>, ProtocolError> {
    let header = input
        .get(..ATTRIBUTES_LEN)
        .ok_or(ProtocolError::InvalidLength)?;
    if header[..2] != VERSION.to_le_bytes() {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let mode = u16::from_le_bytes(header[2..4].try_into().unwrap());
    if mode & !0o7777 != 0 || header[12..].iter().any(|byte| *byte != 0) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(Request {
        mode,
        uid: u32::from_le_bytes(header[4..8].try_into().unwrap()),
        gid: u32::from_le_bytes(header[8..12].try_into().unwrap()),
        identity: device_removal::decode(&input[ATTRIBUTES_LEN..])?,
    })
}
