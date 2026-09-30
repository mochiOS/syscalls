#![no_std]

pub const MAGIC: [u8; 4] = *b"MFS1";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 64;
pub const MAX_MESSAGE_LEN: usize = 256 * 1024;
pub const MAX_PATH_LEN: usize = 4096;

pub const OP_MOUNT: u16 = 1;
pub const OP_UNMOUNT: u16 = 2;
pub const OP_LOOKUP: u16 = 3;
pub const OP_OPEN: u16 = 4;
pub const OP_CLOSE: u16 = 5;
pub const OP_READ: u16 = 6;
pub const OP_WRITE: u16 = 7;
pub const OP_STAT: u16 = 8;
pub const OP_READDIR: u16 = 9;
pub const OP_CREATE: u16 = 10;
pub const OP_UNLINK: u16 = 11;
pub const OP_RENAME: u16 = 12;
pub const OP_SYMLINK: u16 = 13;
pub const OP_READLINK: u16 = 14;
pub const OP_TRUNCATE: u16 = 15;
pub const OP_SYNC: u16 = 16;
pub const OP_STATUS: u16 = 0x8000;

/// `Header::flags` carries the requested byte count for `OP_READ`.
pub const MAX_IO_LEN: usize = MAX_MESSAGE_LEN - HEADER_LEN;

pub const NODE_TYPE_REGULAR: u32 = 1;
pub const NODE_TYPE_DIRECTORY: u32 = 2;
pub const NODE_TYPE_SYMLINK: u32 = 3;
pub const NODE_TYPE_SPECIAL: u32 = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub opcode: u16,
    pub request_id: u64,
    pub mount_id: u64,
    pub node_id: u64,
    pub open_id: u64,
    pub offset: u64,
    pub length: u32,
    pub flags: u32,
    pub status: i32,
    pub mode: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    BufferTooSmall,
    InvalidMagic,
    UnsupportedVersion,
    InvalidLength,
}

pub fn encode(header: Header, payload: &[u8], output: &mut [u8]) -> Result<usize, ProtocolError> {
    if payload.len() > MAX_MESSAGE_LEN - HEADER_LEN || payload.len() != header.length as usize {
        return Err(ProtocolError::InvalidLength);
    }
    let total = HEADER_LEN + payload.len();
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..HEADER_LEN].fill(0);
    output[0..4].copy_from_slice(&MAGIC);
    put_u16(output, 4, VERSION);
    put_u16(output, 6, header.opcode);
    put_u64(output, 8, header.request_id);
    put_u64(output, 16, header.mount_id);
    put_u64(output, 24, header.node_id);
    put_u64(output, 32, header.open_id);
    put_u64(output, 40, header.offset);
    put_u32(output, 48, header.length);
    put_u32(output, 52, header.flags);
    put_u32(output, 56, header.status as u32);
    put_u32(output, 60, header.mode);
    output[HEADER_LEN..total].copy_from_slice(payload);
    Ok(total)
}

pub fn decode(input: &[u8]) -> Result<(Header, &[u8]), ProtocolError> {
    if input.len() < HEADER_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if input[0..4] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    if get_u16(input, 4) != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let length = get_u32(input, 48);
    let total = HEADER_LEN
        .checked_add(length as usize)
        .ok_or(ProtocolError::InvalidLength)?;
    if total > input.len() || total > MAX_MESSAGE_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok((
        Header {
            opcode: get_u16(input, 6),
            request_id: get_u64(input, 8),
            mount_id: get_u64(input, 16),
            node_id: get_u64(input, 24),
            open_id: get_u64(input, 32),
            offset: get_u64(input, 40),
            length,
            flags: get_u32(input, 52),
            status: get_u32(input, 56) as i32,
            mode: get_u32(input, 60),
        },
        &input[HEADER_LEN..total],
    ))
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([input[offset], input[offset + 1]])
}

fn get_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap())
}

fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_handles_and_payload() {
        let payload = b"etc/config.toml";
        let header = Header {
            opcode: OP_LOOKUP,
            request_id: 7,
            mount_id: 11,
            node_id: 13,
            length: payload.len() as u32,
            ..Header::default()
        };
        let mut bytes = [0u8; 128];
        let length = encode(header, payload, &mut bytes).unwrap();
        let (decoded, decoded_payload) = decode(&bytes[..length]).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(decoded_payload, payload);
    }
}
