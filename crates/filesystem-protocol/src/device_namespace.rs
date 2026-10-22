//! Names are single components. Parent authority is an IPC attachment, never
//! a path or numeric inode/open ID; uid/gid are configuration, not identity.
use crate::{
    OP_DEVICE_NODE_CREATE, OP_DEVICE_NODE_REMOVE, OP_DEVICE_NODE_SET_ATTRIBUTES, ProtocolError,
};
pub const HEADER_LEN: usize = 24;
pub const MAX_NAME_LEN: usize = 255;
pub const KIND_DIRECTORY: u16 = 1;
pub const KIND_NULL: u16 = 2;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub kind: u16,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub name: &'a [u8],
}
fn valid(opcode: u16, request: Request<'_>) -> bool {
    let name = request.name;
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name != b"."
        && name != b".."
        && !name.contains(&0)
        && !name.contains(&b'/')
        && request.mode & !0o7777 == 0
        && match opcode {
            OP_DEVICE_NODE_CREATE => matches!(request.kind, KIND_DIRECTORY | KIND_NULL),
            OP_DEVICE_NODE_SET_ATTRIBUTES => request.kind == 0,
            OP_DEVICE_NODE_REMOVE => {
                request.kind == 0 && request.mode == 0 && request.uid == 0 && request.gid == 0
            }
            _ => false,
        }
}
pub fn encode(
    opcode: u16,
    request: Request<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    if !valid(opcode, request) {
        return Err(ProtocolError::InvalidLength);
    }
    let length = HEADER_LEN + request.name.len();
    if output.len() < length {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..length].fill(0);
    output[..2].copy_from_slice(&1u16.to_le_bytes());
    output[2..4].copy_from_slice(&request.kind.to_le_bytes());
    output[4..8].copy_from_slice(&u32::from(request.mode).to_le_bytes());
    output[8..12].copy_from_slice(&request.uid.to_le_bytes());
    output[12..16].copy_from_slice(&request.gid.to_le_bytes());
    output[16..18].copy_from_slice(&(request.name.len() as u16).to_le_bytes());
    output[HEADER_LEN..length].copy_from_slice(request.name);
    Ok(length)
}
pub fn decode(opcode: u16, input: &[u8]) -> Result<Request<'_>, ProtocolError> {
    let header = input
        .get(..HEADER_LEN)
        .ok_or(ProtocolError::InvalidLength)?;
    if header[..2] != 1u16.to_le_bytes() {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let name_len = usize::from(u16::from_le_bytes(header[16..18].try_into().unwrap()));
    if input.len() != HEADER_LEN + name_len || header[18..].iter().any(|byte| *byte != 0) {
        return Err(ProtocolError::InvalidLength);
    }
    let mode = u32::from_le_bytes(header[4..8].try_into().unwrap());
    let request = Request {
        kind: u16::from_le_bytes(header[2..4].try_into().unwrap()),
        mode: u16::try_from(mode).map_err(|_| ProtocolError::InvalidLength)?,
        uid: u32::from_le_bytes(header[8..12].try_into().unwrap()),
        gid: u32::from_le_bytes(header[12..16].try_into().unwrap()),
        name: &input[HEADER_LEN..],
    };
    if !valid(opcode, request) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(request)
}
