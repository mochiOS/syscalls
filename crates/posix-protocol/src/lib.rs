#![no_std]

//! Versioned wire protocol shared by the mochiOS POSIX client and service.
//!
//! The protocol contains no process-local pointers or file-descriptor numbers.
//! Kernel objects travel as IPC handle attachments, outside the byte payload.

pub const MAGIC: [u8; 4] = *b"POSX";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 32;
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// Opaque LaunchContext key under which the POSIX control endpoint is passed.
///
/// This value belongs to the POSIX user-space contract. mnu treats it as an
/// uninterpreted integer.
pub const CONTROL_HANDLE_KEY: u64 = u64::from_le_bytes(*b"POSXCTRL");

pub const OP_PING: u16 = 1;
pub const OP_SESSION_REGISTER: u16 = 2;
pub const OP_STATUS: u16 = 0x8000;

pub const STATUS_OK: i32 = 0;
pub const STATUS_ENOSYS: i32 = -38;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub opcode: u16,
    pub request_id: u64,
    pub flags: u32,
    pub payload_len: u32,
    pub status: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    BufferTooSmall,
    InvalidMagic,
    UnsupportedVersion,
    InvalidLength,
}

pub fn encode(
    header: Header,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    if payload.len() != header.payload_len as usize
        || payload.len() > MAX_MESSAGE_LEN - HEADER_LEN
    {
        return Err(ProtocolError::InvalidLength);
    }
    let total = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }

    output[..HEADER_LEN].fill(0);
    output[0..4].copy_from_slice(&MAGIC);
    put_u16(output, 4, VERSION);
    put_u16(output, 6, header.opcode);
    put_u64(output, 8, header.request_id);
    put_u32(output, 16, header.flags);
    put_u32(output, 20, header.payload_len);
    put_u32(output, 24, header.status as u32);
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

    let payload_len = get_u32(input, 20) as usize;
    let total = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(ProtocolError::InvalidLength)?;
    if total > input.len() || total > MAX_MESSAGE_LEN {
        return Err(ProtocolError::InvalidLength);
    }

    Ok((
        Header {
            opcode: get_u16(input, 6),
            request_id: get_u64(input, 8),
            flags: get_u32(input, 16),
            payload_len: payload_len as u32,
            status: get_u32(input, 24) as i32,
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
