#![no_std]

pub const MAGIC: [u8; 4] = *b"MWSP";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 24;
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;
pub const MAX_CLIPBOARD_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CHUNK_BYTES: usize = MAX_MESSAGE_LEN - HEADER_LEN - 16;
pub const MAX_CONTENT_TYPE_LEN: usize = 127;
pub const MAX_EXTENSION_LEN: usize = 63;
pub const MAX_BUNDLE_ID_LEN: usize = 255;

pub const OP_CLIPBOARD_SET_BEGIN: u16 = 0x0100;
pub const OP_CLIPBOARD_SET_CHUNK: u16 = 0x0101;
pub const OP_CLIPBOARD_SET_COMMIT: u16 = 0x0102;
pub const OP_CLIPBOARD_SNAPSHOT: u16 = 0x0103;
pub const OP_CLIPBOARD_READ: u16 = 0x0104;
pub const OP_ASSOCIATION_SET: u16 = 0x0200;
pub const OP_ASSOCIATION_REMOVE: u16 = 0x0201;
pub const OP_ASSOCIATION_RESOLVE: u16 = 0x0202;

pub const OP_STATUS: u16 = 0x8000;
pub const OP_CLIPBOARD_METADATA: u16 = 0x8103;
pub const OP_CLIPBOARD_CHUNK: u16 = 0x8104;
pub const OP_ASSOCIATION_RESULT: u16 = 0x8202;

pub const ASSOCIATION_ROLE_VIEW: u16 = 1 << 0;
pub const ASSOCIATION_ROLE_EDIT: u16 = 1 << 1;
pub const ASSOCIATION_ROLE_ALL: u16 = ASSOCIATION_ROLE_VIEW | ASSOCIATION_ROLE_EDIT;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    BufferTooSmall,
    InvalidMagic,
    UnsupportedVersion,
    InvalidLength,
    InvalidField,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message<'a> {
    pub opcode: u16,
    pub request_id: u64,
    pub flags: u32,
    pub payload: &'a [u8],
}

pub fn decode(bytes: &[u8]) -> Result<Message<'_>, ProtocolError> {
    if bytes.len() < HEADER_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if bytes[..4] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    let version = read_u16(bytes, 4)?;
    if version != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let payload_len = read_u32(bytes, 16)? as usize;
    let total = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(ProtocolError::InvalidLength)?;
    if total != bytes.len() || total > MAX_MESSAGE_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(Message {
        opcode: read_u16(bytes, 6)?,
        request_id: read_u64(bytes, 8)?,
        flags: read_u32(bytes, 20)?,
        payload: &bytes[HEADER_LEN..total],
    })
}

pub fn encode(
    opcode: u16,
    request_id: u64,
    flags: u32,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let total = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if total > MAX_MESSAGE_LEN || output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..4].copy_from_slice(&MAGIC);
    output[4..6].copy_from_slice(&VERSION.to_le_bytes());
    output[6..8].copy_from_slice(&opcode.to_le_bytes());
    output[8..16].copy_from_slice(&request_id.to_le_bytes());
    output[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    output[20..24].copy_from_slice(&flags.to_le_bytes());
    output[HEADER_LEN..total].copy_from_slice(payload);
    Ok(total)
}

pub fn encode_status(
    request_id: u64,
    status: i32,
    generation: u64,
    value: u64,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let mut payload = [0u8; 24];
    payload[..4].copy_from_slice(&status.to_le_bytes());
    payload[8..16].copy_from_slice(&generation.to_le_bytes());
    payload[16..24].copy_from_slice(&value.to_le_bytes());
    encode(OP_STATUS, request_id, 0, &payload, output)
}

pub fn decode_status(message: Message<'_>) -> Result<(i32, u64, u64), ProtocolError> {
    if message.opcode != OP_STATUS || message.payload.len() != 24 {
        return Err(ProtocolError::InvalidField);
    }
    Ok((
        read_i32(message.payload, 0)?,
        read_u64(message.payload, 8)?,
        read_u64(message.payload, 16)?,
    ))
}

pub fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ProtocolError> {
    let value = bytes.get(offset..offset + 2).ok_or(ProtocolError::InvalidLength)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

pub fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ProtocolError> {
    let value = bytes.get(offset..offset + 4).ok_or(ProtocolError::InvalidLength)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

pub fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, ProtocolError> {
    let value = bytes.get(offset..offset + 4).ok_or(ProtocolError::InvalidLength)?;
    Ok(i32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

pub fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ProtocolError> {
    let value = bytes.get(offset..offset + 8).ok_or(ProtocolError::InvalidLength)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

pub fn validate_utf8_field<'a>(
    bytes: &'a [u8],
    offset: usize,
    length: usize,
    maximum: usize,
) -> Result<&'a str, ProtocolError> {
    if length == 0 || length > maximum {
        return Err(ProtocolError::InvalidField);
    }
    let field = bytes
        .get(offset..offset.checked_add(length).ok_or(ProtocolError::InvalidLength)?)
        .ok_or(ProtocolError::InvalidLength)?;
    core::str::from_utf8(field).map_err(|_| ProtocolError::InvalidField)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_round_trip_has_stable_little_endian_header() {
        let mut encoded = [0u8; 64];
        let length = encode(OP_CLIPBOARD_SNAPSHOT, 0x0102_0304_0506_0708, 3, b"abc", &mut encoded)
            .expect("encode");
        assert_eq!(&encoded[..4], b"MWSP");
        assert_eq!(&encoded[4..8], &[1, 0, 3, 1]);
        assert_eq!(&encoded[8..16], &[8, 7, 6, 5, 4, 3, 2, 1]);
        let decoded = decode(&encoded[..length]).expect("decode");
        assert_eq!(decoded.opcode, OP_CLIPBOARD_SNAPSHOT);
        assert_eq!(decoded.request_id, 0x0102_0304_0506_0708);
        assert_eq!(decoded.flags, 3);
        assert_eq!(decoded.payload, b"abc");
    }

    #[test]
    fn malformed_length_and_unknown_version_are_rejected() {
        let mut encoded = [0u8; 64];
        let length = encode(OP_CLIPBOARD_SNAPSHOT, 1, 0, b"abc", &mut encoded).unwrap();
        encoded[16..20].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(decode(&encoded[..length]), Err(ProtocolError::InvalidLength));
        encoded[16..20].copy_from_slice(&3u32.to_le_bytes());
        encoded[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(decode(&encoded[..length]), Err(ProtocolError::UnsupportedVersion));
    }
}
