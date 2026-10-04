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

const FD_HANDLE_KEY_PREFIX: u64 = 0x504f_5348_0000_0000;
const FD_FLAGS_KEY_PREFIX: u64 = 0x504f_5346_0000_0000;
const FD_RIGHTS_KEY_PREFIX: u64 = 0x504f_5352_0000_0000;
const FD_KEY_INDEX_MASK: u64 = u32::MAX as u64;

pub const fn fd_handle_key(fd: i32) -> Option<u64> {
    if fd < 0 {
        return None;
    }
    Some(FD_HANDLE_KEY_PREFIX | fd as u32 as u64)
}

pub const fn fd_flags_key(fd: i32) -> Option<u64> {
    if fd < 0 {
        return None;
    }
    Some(FD_FLAGS_KEY_PREFIX | fd as u32 as u64)
}

pub const fn fd_rights_key(fd: i32) -> Option<u64> {
    if fd < 0 {
        return None;
    }
    Some(FD_RIGHTS_KEY_PREFIX | fd as u32 as u64)
}

pub const fn encode_fd_flags(open_flags: u32, descriptor_flags: u32) -> u64 {
    open_flags as u64 | ((descriptor_flags as u64) << 32)
}

pub const fn decode_fd_flags(value: u64) -> (u32, u32) {
    (value as u32, (value >> 32) as u32)
}

pub const fn inherited_fd_from_key(key: u64) -> Option<i32> {
    let prefix = key & !FD_KEY_INDEX_MASK;
    if prefix != FD_HANDLE_KEY_PREFIX
        && prefix != FD_FLAGS_KEY_PREFIX
        && prefix != FD_RIGHTS_KEY_PREFIX
    {
        return None;
    }
    let index = (key & FD_KEY_INDEX_MASK) as u32;
    if index > i32::MAX as u32 {
        return None;
    }
    Some(index as i32)
}

pub const OP_PING: u16 = 1;
pub const OP_SESSION_REGISTER: u16 = 2;
pub const OP_SESSION_INFO: u16 = 3;
pub const OP_UMASK_SET: u16 = 4;
pub const OP_OPEN_AT: u16 = 5;
pub const OP_STAT_AT: u16 = 6;
pub const OP_FSTAT: u16 = 7;
pub const OP_ACCESS_AT: u16 = 8;
pub const OP_CHDIR_AT: u16 = 9;
pub const OP_FCHDIR: u16 = 10;
pub const OP_GETCWD: u16 = 11;
pub const OP_SET_UID: u16 = 12;
pub const OP_SET_GID: u16 = 13;
pub const OP_FTRUNCATE: u16 = 14;
pub const OP_FSYNC: u16 = 15;
pub const OP_FGETFL: u16 = 16;
pub const OP_FSETFL: u16 = 17;
pub const OP_MKDIR_AT: u16 = 18;
pub const OP_UNLINK_AT: u16 = 19;
pub const OP_RENAME_AT: u16 = 20;
pub const OP_TRUNCATE_AT: u16 = 21;
pub const OP_STATUS: u16 = 0x8000;

pub const STATUS_OK: i32 = 0;
pub const STATUS_ENOENT: i32 = -2;
pub const STATUS_ESRCH: i32 = -3;
pub const STATUS_ENOSYS: i32 = -38;

pub const SESSION_INFO_LEN: usize = 20;
pub const UMASK_PAYLOAD_LEN: usize = 4;
pub const CREDENTIAL_ID_PAYLOAD_LEN: usize = 4;
pub const FILE_LENGTH_PAYLOAD_LEN: usize = 8;
pub const FILE_FLAGS_PAYLOAD_LEN: usize = 4;
pub const OPEN_AT_HEADER_LEN: usize = 16;
pub const STAT_AT_HEADER_LEN: usize = 12;
pub const ACCESS_AT_HEADER_LEN: usize = 16;
pub const RENAME_AT_HEADER_LEN: usize = 16;
pub const TRUNCATE_AT_HEADER_LEN: usize = 16;
pub const FILE_STATUS_LEN: usize = 112;
pub const MAX_PATH_LEN: usize = 4096;
pub const MAX_CONTROL_PAYLOAD_LEN: usize = RENAME_AT_HEADER_LEN + MAX_PATH_LEN * 2;
pub const CONTROL_MESSAGE_LEN: usize = HEADER_LEN + MAX_CONTROL_PAYLOAD_LEN;

pub const STAT_NOFOLLOW: u32 = 1 << 0;
pub const STAT_FLAGS_ALL: u32 = STAT_NOFOLLOW;

pub const ACCESS_READ: u32 = 1 << 2;
pub const ACCESS_WRITE: u32 = 1 << 1;
pub const ACCESS_EXECUTE: u32 = 1 << 0;
pub const ACCESS_MODES_ALL: u32 = ACCESS_READ | ACCESS_WRITE | ACCESS_EXECUTE;
pub const ACCESS_EFFECTIVE_IDS: u32 = 1 << 0;
pub const ACCESS_NOFOLLOW: u32 = 1 << 1;
pub const ACCESS_FLAGS_ALL: u32 = ACCESS_EFFECTIVE_IDS | ACCESS_NOFOLLOW;

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

pub const MUTABLE_STATUS_FLAGS: u32 = OPEN_APPEND | OPEN_NONBLOCK;

pub const UNLINK_REMOVE_DIRECTORY: u32 = 1 << 0;
pub const UNLINK_FLAGS_ALL: u32 = UNLINK_REMOVE_DIRECTORY;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatAtRequest<'a> {
    pub base: OpenBase,
    pub flags: u32,
    pub path: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessAtRequest<'a> {
    pub base: OpenBase,
    pub flags: u32,
    pub modes: u32,
    pub path: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenameAtRequest<'a> {
    pub old_base: OpenBase,
    pub new_base: OpenBase,
    pub old_path: &'a str,
    pub new_path: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TruncateAtRequest<'a> {
    pub base: OpenBase,
    pub length: u64,
    pub path: &'a str,
}

/// Architecture-independent representation of the POSIX `struct stat` data.
///
/// This structure is serialized field by field. It is never copied as a Rust
/// structure and therefore does not expose compiler padding or a target ABI.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileStatus {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub link_count: u32,
    pub uid: u32,
    pub gid: u32,
    pub special_device: u64,
    pub size: i64,
    pub block_size: i64,
    pub blocks: i64,
    pub access_time_seconds: i64,
    pub access_time_nanoseconds: i64,
    pub modification_time_seconds: i64,
    pub modification_time_nanoseconds: i64,
    pub change_time_seconds: i64,
    pub change_time_nanoseconds: i64,
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

pub fn encode_credential_id(value: u32, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < CREDENTIAL_ID_PAYLOAD_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, value);
    Ok(())
}

pub fn decode_credential_id(input: &[u8]) -> Result<u32, ProtocolError> {
    if input.len() != CREDENTIAL_ID_PAYLOAD_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(get_u32(input, 0))
}

pub fn encode_file_length(value: u64, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < FILE_LENGTH_PAYLOAD_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u64(output, 0, value);
    Ok(())
}

pub fn decode_file_length(input: &[u8]) -> Result<u64, ProtocolError> {
    if input.len() != FILE_LENGTH_PAYLOAD_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(get_u64(input, 0))
}

pub fn encode_file_flags(value: u32, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < FILE_FLAGS_PAYLOAD_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, value);
    Ok(())
}

pub fn decode_file_flags(input: &[u8]) -> Result<u32, ProtocolError> {
    if input.len() != FILE_FLAGS_PAYLOAD_LEN {
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

pub fn encode_stat_at(
    request: StatAtRequest<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let path = request.path.as_bytes();
    if path.is_empty()
        || path.len() > MAX_PATH_LEN
        || path.contains(&0)
        || request.flags & !STAT_FLAGS_ALL != 0
    {
        return Err(ProtocolError::InvalidLength);
    }
    let total = STAT_AT_HEADER_LEN
        .checked_add(path.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..STAT_AT_HEADER_LEN].fill(0);
    output[0] = request.base as u8;
    put_u32(output, 4, request.flags);
    put_u32(output, 8, path.len() as u32);
    output[STAT_AT_HEADER_LEN..total].copy_from_slice(path);
    Ok(total)
}

pub fn decode_stat_at(input: &[u8]) -> Result<StatAtRequest<'_>, ProtocolError> {
    if input.len() < STAT_AT_HEADER_LEN || input[1..4] != [0; 3] {
        return Err(ProtocolError::InvalidLength);
    }
    let base = OpenBase::from_raw(input[0]).ok_or(ProtocolError::InvalidLength)?;
    let flags = get_u32(input, 4);
    if flags & !STAT_FLAGS_ALL != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    let path_len = get_u32(input, 8) as usize;
    if path_len == 0 || path_len > MAX_PATH_LEN || input.len() != STAT_AT_HEADER_LEN + path_len {
        return Err(ProtocolError::InvalidLength);
    }
    let path_bytes = &input[STAT_AT_HEADER_LEN..];
    if path_bytes.contains(&0) {
        return Err(ProtocolError::InvalidLength);
    }
    let path = core::str::from_utf8(path_bytes).map_err(|_| ProtocolError::InvalidLength)?;
    Ok(StatAtRequest { base, flags, path })
}

pub fn encode_rename_at(
    request: RenameAtRequest<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let old_path = request.old_path.as_bytes();
    let new_path = request.new_path.as_bytes();
    if old_path.is_empty()
        || new_path.is_empty()
        || old_path.len() > MAX_PATH_LEN
        || new_path.len() > MAX_PATH_LEN
        || old_path.contains(&0)
        || new_path.contains(&0)
    {
        return Err(ProtocolError::InvalidLength);
    }
    let total = RENAME_AT_HEADER_LEN
        .checked_add(old_path.len())
        .and_then(|length| length.checked_add(new_path.len()))
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..RENAME_AT_HEADER_LEN].fill(0);
    output[0] = request.old_base as u8;
    output[1] = request.new_base as u8;
    put_u32(output, 8, old_path.len() as u32);
    put_u32(output, 12, new_path.len() as u32);
    output[RENAME_AT_HEADER_LEN..RENAME_AT_HEADER_LEN + old_path.len()]
        .copy_from_slice(old_path);
    output[RENAME_AT_HEADER_LEN + old_path.len()..total].copy_from_slice(new_path);
    Ok(total)
}

pub fn decode_rename_at(input: &[u8]) -> Result<RenameAtRequest<'_>, ProtocolError> {
    if input.len() < RENAME_AT_HEADER_LEN || input[2..8] != [0; 6] {
        return Err(ProtocolError::InvalidLength);
    }
    let old_base = OpenBase::from_raw(input[0]).ok_or(ProtocolError::InvalidLength)?;
    let new_base = OpenBase::from_raw(input[1]).ok_or(ProtocolError::InvalidLength)?;
    let old_len = get_u32(input, 8) as usize;
    let new_len = get_u32(input, 12) as usize;
    if old_len == 0
        || new_len == 0
        || old_len > MAX_PATH_LEN
        || new_len > MAX_PATH_LEN
        || input.len() != RENAME_AT_HEADER_LEN + old_len + new_len
    {
        return Err(ProtocolError::InvalidLength);
    }
    let old_bytes = &input[RENAME_AT_HEADER_LEN..RENAME_AT_HEADER_LEN + old_len];
    let new_bytes = &input[RENAME_AT_HEADER_LEN + old_len..];
    if old_bytes.contains(&0) || new_bytes.contains(&0) {
        return Err(ProtocolError::InvalidLength);
    }
    let old_path = core::str::from_utf8(old_bytes).map_err(|_| ProtocolError::InvalidLength)?;
    let new_path = core::str::from_utf8(new_bytes).map_err(|_| ProtocolError::InvalidLength)?;
    Ok(RenameAtRequest {
        old_base,
        new_base,
        old_path,
        new_path,
    })
}

pub fn encode_truncate_at(
    request: TruncateAtRequest<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let path = request.path.as_bytes();
    if path.is_empty() || path.len() > MAX_PATH_LEN || path.contains(&0) {
        return Err(ProtocolError::InvalidLength);
    }
    let total = TRUNCATE_AT_HEADER_LEN
        .checked_add(path.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..TRUNCATE_AT_HEADER_LEN].fill(0);
    output[0] = request.base as u8;
    put_u64(output, 4, request.length);
    put_u32(output, 12, path.len() as u32);
    output[TRUNCATE_AT_HEADER_LEN..total].copy_from_slice(path);
    Ok(total)
}

pub fn decode_truncate_at(input: &[u8]) -> Result<TruncateAtRequest<'_>, ProtocolError> {
    if input.len() < TRUNCATE_AT_HEADER_LEN || input[1..4] != [0; 3] {
        return Err(ProtocolError::InvalidLength);
    }
    let base = OpenBase::from_raw(input[0]).ok_or(ProtocolError::InvalidLength)?;
    let length = get_u64(input, 4);
    let path_len = get_u32(input, 12) as usize;
    if path_len == 0 || path_len > MAX_PATH_LEN || input.len() != TRUNCATE_AT_HEADER_LEN + path_len {
        return Err(ProtocolError::InvalidLength);
    }
    let path_bytes = &input[TRUNCATE_AT_HEADER_LEN..];
    if path_bytes.contains(&0) {
        return Err(ProtocolError::InvalidLength);
    }
    let path = core::str::from_utf8(path_bytes).map_err(|_| ProtocolError::InvalidLength)?;
    Ok(TruncateAtRequest { base, length, path })
}

pub fn encode_access_at(
    request: AccessAtRequest<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let path = request.path.as_bytes();
    if path.is_empty()
        || path.len() > MAX_PATH_LEN
        || path.contains(&0)
        || request.flags & !ACCESS_FLAGS_ALL != 0
        || request.modes & !ACCESS_MODES_ALL != 0
    {
        return Err(ProtocolError::InvalidLength);
    }
    let total = ACCESS_AT_HEADER_LEN
        .checked_add(path.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..ACCESS_AT_HEADER_LEN].fill(0);
    output[0] = request.base as u8;
    put_u32(output, 4, request.flags);
    put_u32(output, 8, request.modes);
    put_u32(output, 12, path.len() as u32);
    output[ACCESS_AT_HEADER_LEN..total].copy_from_slice(path);
    Ok(total)
}

pub fn decode_access_at(input: &[u8]) -> Result<AccessAtRequest<'_>, ProtocolError> {
    if input.len() < ACCESS_AT_HEADER_LEN || input[1..4] != [0; 3] {
        return Err(ProtocolError::InvalidLength);
    }
    let base = OpenBase::from_raw(input[0]).ok_or(ProtocolError::InvalidLength)?;
    let flags = get_u32(input, 4);
    let modes = get_u32(input, 8);
    if flags & !ACCESS_FLAGS_ALL != 0 || modes & !ACCESS_MODES_ALL != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    let path_len = get_u32(input, 12) as usize;
    if path_len == 0 || path_len > MAX_PATH_LEN || input.len() != ACCESS_AT_HEADER_LEN + path_len {
        return Err(ProtocolError::InvalidLength);
    }
    let path_bytes = &input[ACCESS_AT_HEADER_LEN..];
    if path_bytes.contains(&0) {
        return Err(ProtocolError::InvalidLength);
    }
    let path = core::str::from_utf8(path_bytes).map_err(|_| ProtocolError::InvalidLength)?;
    Ok(AccessAtRequest {
        base,
        flags,
        modes,
        path,
    })
}

pub fn encode_file_status(status: FileStatus, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < FILE_STATUS_LEN || !timestamps_are_valid(&status) {
        return Err(if output.len() < FILE_STATUS_LEN {
            ProtocolError::BufferTooSmall
        } else {
            ProtocolError::InvalidLength
        });
    }
    output[..FILE_STATUS_LEN].fill(0);
    put_u64(output, 0, status.device);
    put_u64(output, 8, status.inode);
    put_u32(output, 16, status.mode);
    put_u32(output, 20, status.link_count);
    put_u32(output, 24, status.uid);
    put_u32(output, 28, status.gid);
    put_u64(output, 32, status.special_device);
    put_i64(output, 40, status.size);
    put_i64(output, 48, status.block_size);
    put_i64(output, 56, status.blocks);
    put_i64(output, 64, status.access_time_seconds);
    put_i64(output, 72, status.access_time_nanoseconds);
    put_i64(output, 80, status.modification_time_seconds);
    put_i64(output, 88, status.modification_time_nanoseconds);
    put_i64(output, 96, status.change_time_seconds);
    put_i64(output, 104, status.change_time_nanoseconds);
    Ok(())
}

pub fn decode_file_status(input: &[u8]) -> Result<FileStatus, ProtocolError> {
    if input.len() != FILE_STATUS_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let status = FileStatus {
        device: get_u64(input, 0),
        inode: get_u64(input, 8),
        mode: get_u32(input, 16),
        link_count: get_u32(input, 20),
        uid: get_u32(input, 24),
        gid: get_u32(input, 28),
        special_device: get_u64(input, 32),
        size: get_i64(input, 40),
        block_size: get_i64(input, 48),
        blocks: get_i64(input, 56),
        access_time_seconds: get_i64(input, 64),
        access_time_nanoseconds: get_i64(input, 72),
        modification_time_seconds: get_i64(input, 80),
        modification_time_nanoseconds: get_i64(input, 88),
        change_time_seconds: get_i64(input, 96),
        change_time_nanoseconds: get_i64(input, 104),
    };
    if !timestamps_are_valid(&status) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(status)
}

fn timestamps_are_valid(status: &FileStatus) -> bool {
    [
        status.access_time_nanoseconds,
        status.modification_time_nanoseconds,
        status.change_time_nanoseconds,
    ]
    .into_iter()
    .all(|nanoseconds| (0..1_000_000_000).contains(&nanoseconds))
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

fn put_i64(output: &mut [u8], offset: usize, value: i64) {
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

fn get_i64(input: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(input[offset..offset + 8].try_into().unwrap())
}
