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
pub const OP_SESSION_INFO: u16 = 3;
pub const OP_UMASK_SET: u16 = 4;
pub const OP_OPEN_AT: u16 = 5;
pub const OP_STATUS: u16 = 0x8000;

pub const STATUS_OK: i32 = 0;
pub const STATUS_ENOENT: i32 = -2;
pub const STATUS_ESRCH: i32 = -3;
pub const STATUS_ENOSYS: i32 = -38;

pub const SESSION_INFO_LEN: usize = 20;
pub const UMASK_PAYLOAD_LEN: usize = 4;
pub const OPEN_AT_HEADER_LEN: usize = 16;
pub const MAX_PATH_LEN: usize = 4096;

pub const OPEN_READ: u32 = 1 << 0;
pub const OPEN_WRITE: u32 = 1 << 1;
pub const OPEN_CREATE: u32 = 1 << 2;
pub const OPEN_EXCLUSIVE: u32 = 1 << 3;
pub const OPEN_TRUNCATE: u32 = 1 << 4;
pub const OPEN_APPEND: u32 = 1 << 5;
pub const OPEN_NONBLOCK: u32 = 1 << 6;
pub const OPEN_DIRECTORY: u32 = 1 << 7;
pub const OPEN_NOFOLLOW: u32 = 1 << 8;
pub const OPEN_OPTIONS_ALL: u32 = OPEN_READ
    | OPEN_WRITE
    | OPEN_CREATE
    | OPEN_EXCLUSIVE
    | OPEN_TRUNCATE
    | OPEN_APPEND
    | OPEN_NONBLOCK
    | OPEN_DIRECTORY
    | OPEN_NOFOLLOW;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenBase {
    ProcessRoot = 0,
    ProcessCwd = 1,
    AttachedDirectory = 2,
}

impl OpenBase {
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::ProcessRoot),
            1 => Some(Self::ProcessCwd),
            2 => Some(Self::AttachedDirectory),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenAtRequest<'a> {
    pub base: OpenBase,
    pub options: u32,
    pub mode: u32,
    pub path: &'a str,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionInfo {
    pub real_uid: u32,
    pub effective_uid: u32,
    pub real_gid: u32,
    pub effective_gid: u32,
    pub umask: u32,
}

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

pub fn encode_session_info(info: SessionInfo, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < SESSION_INFO_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, info.real_uid);
    put_u32(output, 4, info.effective_uid);
    put_u32(output, 8, info.real_gid);
    put_u32(output, 12, info.effective_gid);
    put_u32(output, 16, info.umask);
    Ok(())
}

pub fn decode_session_info(input: &[u8]) -> Result<SessionInfo, ProtocolError> {
    if input.len() != SESSION_INFO_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(SessionInfo {
        real_uid: get_u32(input, 0),
        effective_uid: get_u32(input, 4),
        real_gid: get_u32(input, 8),
        effective_gid: get_u32(input, 12),
        umask: get_u32(input, 16),
    })
}

pub fn encode_umask(value: u32, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < UMASK_PAYLOAD_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, value);
    Ok(())
}

pub fn decode_umask(input: &[u8]) -> Result<u32, ProtocolError> {
    if input.len() != UMASK_PAYLOAD_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(get_u32(input, 0))
}

pub fn encode_open_at(
    request: OpenAtRequest<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let path = request.path.as_bytes();
    if path.is_empty()
        || path.len() > MAX_PATH_LEN
        || path.contains(&0)
        || request.options & !OPEN_OPTIONS_ALL != 0
    {
        return Err(ProtocolError::InvalidLength);
    }
    let total = OPEN_AT_HEADER_LEN
        .checked_add(path.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..OPEN_AT_HEADER_LEN].fill(0);
    output[0] = request.base as u8;
    put_u32(output, 4, request.options);
    put_u32(output, 8, request.mode);
    put_u32(output, 12, path.len() as u32);
    output[OPEN_AT_HEADER_LEN..total].copy_from_slice(path);
    Ok(total)
}

pub fn decode_open_at(input: &[u8]) -> Result<OpenAtRequest<'_>, ProtocolError> {
    if input.len() < OPEN_AT_HEADER_LEN || input[1..4] != [0; 3] {
        return Err(ProtocolError::InvalidLength);
    }
    let base = OpenBase::from_raw(input[0]).ok_or(ProtocolError::InvalidLength)?;
    let options = get_u32(input, 4);
    if options & !OPEN_OPTIONS_ALL != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    let path_len = get_u32(input, 12) as usize;
    if path_len == 0 || path_len > MAX_PATH_LEN || input.len() != OPEN_AT_HEADER_LEN + path_len {
        return Err(ProtocolError::InvalidLength);
    }
    let path_bytes = &input[OPEN_AT_HEADER_LEN..];
    if path_bytes.contains(&0) {
        return Err(ProtocolError::InvalidLength);
    }
    let path = core::str::from_utf8(path_bytes).map_err(|_| ProtocolError::InvalidLength)?;
    Ok(OpenAtRequest {
        base,
        options,
        mode: get_u32(input, 8),
        path,
    })
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
