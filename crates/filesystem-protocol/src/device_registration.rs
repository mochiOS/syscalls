//! Register an external character device under an attached parent directory.
//! uid/gid/rdev are configured metadata, never authentication information.
use crate::ProtocolError;
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 32;
pub const MAX_NAME_LEN: usize = 255;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub special_device: u64,
    pub name: &'a [u8],
}
fn valid(request: Request<'_>) -> bool {
    let name = request.name;
    request.mode & !0o7777 == 0
        && !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name != b"."
        && name != b".."
        && !name.contains(&0)
        && !name.contains(&b'/')
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
    output[4..8].copy_from_slice(&u32::from(request.mode).to_le_bytes());
    output[8..12].copy_from_slice(&request.uid.to_le_bytes());
    output[12..16].copy_from_slice(&request.gid.to_le_bytes());
    output[16..24].copy_from_slice(&request.special_device.to_le_bytes());
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
        || header[2..4] != [0, 0]
        || header[26..].iter().any(|b| *b != 0)
    {
        return Err(ProtocolError::InvalidLength);
    }
    let request = Request {
        mode: u16::try_from(u32::from_le_bytes(header[4..8].try_into().unwrap()))
            .map_err(|_| ProtocolError::InvalidLength)?,
        uid: u32::from_le_bytes(header[8..12].try_into().unwrap()),
        gid: u32::from_le_bytes(header[12..16].try_into().unwrap()),
        special_device: u64::from_le_bytes(header[16..24].try_into().unwrap()),
        name: &input[HEADER_LEN..],
    };
    if !valid(request) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(request)
}
