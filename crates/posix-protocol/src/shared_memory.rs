//! Named RAM requests contain only serialized names and options. The reply
//! delegates a native object through IPC, never a path, PID or FD number.

use super::{ProtocolError, get_u32, put_u32};

pub use super::named_semaphore::{MAX_NAME_BYTES, NAME_HEADER_LEN, decode_name, encode_name};
pub const OPEN_HEADER_LEN: usize = 16;
pub const READ_WRITE: u32 = 1;
pub const CREATE: u32 = 2;
pub const EXCLUSIVE: u32 = 4;
pub const TRUNCATE: u32 = 8;

/// Provider control codes interpreted only by the userspace POSIX layer.
/// LENGTH: empty input, exactly eight output bytes (little-endian u64).
/// RESIZE: exactly eight input bytes (little-endian u64), no output bytes.
pub const CONTROL_LENGTH: u64 = u64::from_le_bytes(*b"SHMLEN01");
pub const CONTROL_RESIZE: u64 = u64::from_le_bytes(*b"SHMSIZ01");
/// GET_FLAGS: empty input, four output bytes. SET_FLAGS: four input bytes,
/// empty output. Flags are POSIX protocol OPEN_APPEND / OPEN_NONBLOCK bits.
pub const CONTROL_GET_FLAGS: u64 = u64::from_le_bytes(*b"SHMFGT01");
pub const CONTROL_SET_FLAGS: u64 = u64::from_le_bytes(*b"SHMFST01");
/// FILE_FLAGS_UPDATE_PAYLOAD_LEN input (mask, flags), empty output.
pub const CONTROL_UPDATE_FLAGS: u64 = u64::from_le_bytes(*b"SHMFUP01");
/// STAT: empty input; FILE_STATUS_LEN output bytes encoded as FileStatus.
pub const CONTROL_STAT: u64 = u64::from_le_bytes(*b"SHMSTA01");

pub fn descriptor_rights(read_write: bool) -> u64 {
    mnu_abi::HANDLE_RIGHT_READ
        | mnu_abi::HANDLE_RIGHT_SEEK
        | mnu_abi::HANDLE_RIGHT_CONTROL
        | mnu_abi::HANDLE_RIGHT_DUPLICATE
        | mnu_abi::HANDLE_RIGHT_TRANSFER
        | if read_write {
            mnu_abi::HANDLE_RIGHT_WRITE
        } else {
            0
        }
}

pub fn mapping_rights(writable: bool) -> u64 {
    mnu_abi::HANDLE_RIGHT_READ
        | mnu_abi::HANDLE_RIGHT_MAP
        | mnu_abi::HANDLE_RIGHT_DUPLICATE
        | mnu_abi::HANDLE_RIGHT_TRANSFER
        | if writable {
            mnu_abi::HANDLE_RIGHT_WRITE
        } else {
            0
        }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Open<'a> {
    pub options: u32,
    pub mode: u32,
    pub name: &'a [u8],
}

fn valid(request: Open<'_>) -> bool {
    let name = request.name;
    name.first() == Some(&b'/')
        && (2..=MAX_NAME_BYTES + 1).contains(&name.len())
        && !name[1..].iter().any(|byte| matches!(byte, b'/' | 0))
        && request.options & !(READ_WRITE | CREATE | EXCLUSIVE | TRUNCATE) == 0
        && (request.options & EXCLUSIVE == 0 || request.options & CREATE != 0)
        && (request.options & TRUNCATE == 0 || request.options & READ_WRITE != 0)
        && (request.options & CREATE != 0 || request.mode == 0)
}

pub fn encode_open(request: Open<'_>, output: &mut [u8]) -> Result<usize, ProtocolError> {
    if !valid(request) {
        return Err(ProtocolError::InvalidLength);
    }
    let length = OPEN_HEADER_LEN + request.name.len();
    if output.len() < length {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, request.options);
    put_u32(output, 4, request.mode);
    put_u32(output, 8, 0);
    put_u32(output, 12, request.name.len() as u32);
    output[OPEN_HEADER_LEN..length].copy_from_slice(request.name);
    Ok(length)
}

pub fn decode_open(input: &[u8]) -> Result<Open<'_>, ProtocolError> {
    if input.len() < OPEN_HEADER_LEN || get_u32(input, 8) != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    let request = Open {
        options: get_u32(input, 0),
        mode: get_u32(input, 4),
        name: &input[OPEN_HEADER_LEN..],
    };
    if get_u32(input, 12) as usize != request.name.len() || !valid(request) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(request)
}
