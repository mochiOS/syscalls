#![no_std]

mod timestamps;
pub use timestamps::{
    FileTimeUpdate, TIME_UPDATE_LEN, TimestampUpdate, decode_time_update, encode_time_update,
};

pub const MAGIC: [u8; 4] = *b"MFS1";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 64;
pub const MAX_MESSAGE_LEN: usize = 256 * 1024;
pub const MAX_PATH_LEN: usize = 4096;
pub const MAX_SUPPLEMENTARY_GROUPS: usize = 32;
pub const CREDENTIALS_HEADER_LEN: usize = 12;
pub const CREDENTIALS_MAX_LEN: usize =
    CREDENTIALS_HEADER_LEN + MAX_SUPPLEMENTARY_GROUPS * core::mem::size_of::<u32>();

/// Opaque LaunchContext key used to pass the filesystem control endpoint to
/// another user-space service. mnu does not interpret this value.
pub const CONTROL_HANDLE_KEY: u64 = u64::from_le_bytes(*b"MFS1CTRL");

/// Private read-only boot-generation endpoint, explicitly delegated by its
/// user-space owner. READ/READDIR carry absolute path payloads with object IDs
/// zero; flags carry a bounded byte budget. This key has no kernel meaning.
pub const BOOTSTRAP_READ_HANDLE_KEY: u64 = u64::from_le_bytes(*b"MFS1BOOT");
/// Bootstrap messages fit the standard inline IPC budget without increasing
/// kernel mailbox capacity. Larger files are read using independent ranges.
pub const BOOTSTRAP_MAX_TRANSFER: usize = 8 * 1024 - HEADER_LEN;
/// EOF flag on bootstrap OP_STATUS replies only.
pub const BOOTSTRAP_EOF: u32 = 1;

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
pub const OP_SETATTR: u16 = 17;
/// Atomically resolves, optionally creates, and opens one path. Optional root
/// and base provider-owned directory Handles are carried as IPC attachments,
/// in that order.
pub const OP_OPEN_AT: u16 = 18;
/// Atomically resolves a path and returns its metadata. An optional
/// provider-owned directory Handle is carried as an IPC attachment.
pub const OP_STAT_AT: u16 = 19;
/// Returns metadata for exactly one attached provider-owned open object.
pub const OP_STAT_HANDLE: u16 = 20;
/// Atomically resolves a path and checks native filesystem permission bits
/// using credentials authenticated by the calling policy service.
pub const OP_ACCESS_AT: u16 = 21;
/// Returns the absolute path of an attached open directory relative to an
/// attached process root. Attachments are ordered as root, then directory.
pub const OP_PATH_HANDLE: u16 = 22;
/// Truncates exactly one attached provider-owned open object.
pub const OP_TRUNCATE_HANDLE: u16 = 23;
/// Flushes storage after validating one attached provider-owned open object.
pub const OP_SYNC_HANDLE: u16 = 24;
/// Returns status flags stored on exactly one attached open file description.
pub const OP_GET_FLAGS_HANDLE: u16 = 25;
/// Replaces mutable status flags on exactly one attached open file description.
pub const OP_SET_FLAGS_HANDLE: u16 = 26;
/// Atomically resolves a parent directory and creates one directory within it.
pub const OP_MKDIR_AT: u16 = 27;
/// Atomically resolves and removes one directory entry.
pub const OP_UNLINK_AT: u16 = 28;
/// Atomically renames one directory entry between two Handle-anchored paths.
pub const OP_RENAME_AT: u16 = 29;
/// Atomically resolves and truncates one Handle-anchored path.
pub const OP_TRUNCATE_AT: u16 = 30;
/// Atomically creates a symbolic link at a Handle-anchored path.
pub const OP_SYMLINK_AT: u16 = 31;
/// Atomically resolves a Handle-anchored path without following its final
/// component and returns the symbolic-link target.
pub const OP_READLINK_AT: u16 = 32;
/// Atomically changes mode bits on a Handle-anchored path.
pub const OP_CHMOD_AT: u16 = 33;
/// Atomically changes ownership on a Handle-anchored path.
pub const OP_CHOWN_AT: u16 = 34;
/// Changes mode bits on one attached provider-owned open object.
pub const OP_CHMOD_HANDLE: u16 = 35;
/// Changes ownership on one attached provider-owned open object.
pub const OP_CHOWN_HANDLE: u16 = 36;
/// Atomically creates a hard link between two Handle-anchored paths.
pub const OP_LINK_AT: u16 = 37;
/// Creates one exclusive socket inode after Handle-anchored path traversal.
/// Success returns its NodeStatus and one retained metadata-only Provider
/// Handle with DUPLICATE | TRANSFER rights, not byte I/O or mapping rights.
/// Only explicitly delegated filesystem-control holders may supply credentials.
pub const OP_CREATE_SOCKET_AT: u16 = 38;
/// Resolves an existing socket inode, checks search/write permission, and
/// returns NodeStatus plus a retained metadata-only Handle. Uses SOCKET_AT
/// root/base flags; credentials require the delegated control endpoint.
pub const OP_OPEN_SOCKET_AT: u16 = 39;
/// Updates selected mutable OFD status flags. Header.flags supplies the value;
/// the four-byte little-endian payload supplies the mask. One explicit Handle
/// CONTROL|TRANSFER attachment identifies the open description; inline IDs
/// confer no authority. Removing CONTROL prevents changes to shared flags.
pub const OP_UPDATE_FLAGS_HANDLE: u16 = 40;
/// Resolve an existing path, following symlinks, and return its canonical
/// root-relative name. Uses STAT_AT root/base flags and authenticated credentials.
pub const OP_CANONICAL_PATH_AT: u16 = 41;
/// Resolve and update inode times in one operation. Payload: authenticated
/// credentials, FileTimeUpdate, then path. Ordered root/base directory Handles
/// must match SET_TIMES_AT flags. Current time is chosen by the provider.
pub const OP_SET_TIMES_AT: u16 = 42;
/// Update exactly one attached open object. Requires CONTROL|TRANSFER authority;
/// payload: authenticated credentials and FileTimeUpdate, with no trailing data.
pub const OP_SET_TIMES_HANDLE: u16 = 43;
pub const OP_STATUS: u16 = 0x8000;

pub const OPEN_STATUS_APPEND: u32 = 1 << 0;
pub const OPEN_STATUS_NONBLOCK: u32 = 1 << 1;
pub const OPEN_STATUS_FLAGS_ALL: u32 = OPEN_STATUS_APPEND | OPEN_STATUS_NONBLOCK;

pub const MKDIR_AT_BASE_ATTACHED: u32 = 1 << 0;
pub const MKDIR_AT_ROOT_ATTACHED: u32 = 1 << 1;
pub const MKDIR_AT_FLAGS_ALL: u32 = MKDIR_AT_BASE_ATTACHED | MKDIR_AT_ROOT_ATTACHED;
/// Socket-node creation uses the same ordered root/base directory attachments.
pub const SOCKET_AT_BASE_ATTACHED: u32 = 1 << 0;
pub const SOCKET_AT_ROOT_ATTACHED: u32 = 1 << 1;
pub const SOCKET_AT_FLAGS_ALL: u32 = SOCKET_AT_BASE_ATTACHED | SOCKET_AT_ROOT_ATTACHED;

pub const UNLINK_AT_REMOVE_DIRECTORY: u32 = 1 << 0;
pub const UNLINK_AT_BASE_ATTACHED: u32 = 1 << 1;
pub const UNLINK_AT_ROOT_ATTACHED: u32 = 1 << 2;
pub const UNLINK_AT_FLAGS_ALL: u32 = UNLINK_AT_REMOVE_DIRECTORY
    | UNLINK_AT_BASE_ATTACHED
    | UNLINK_AT_ROOT_ATTACHED;

pub const RENAME_AT_OLD_BASE_ATTACHED: u32 = 1 << 0;
pub const RENAME_AT_NEW_BASE_ATTACHED: u32 = 1 << 1;
pub const RENAME_AT_ROOT_ATTACHED: u32 = 1 << 2;
pub const RENAME_AT_FLAGS_ALL: u32 = RENAME_AT_OLD_BASE_ATTACHED
    | RENAME_AT_NEW_BASE_ATTACHED
    | RENAME_AT_ROOT_ATTACHED;

pub const LINK_AT_FOLLOW_SOURCE: u32 = 1 << 0;
pub const LINK_AT_OLD_BASE_ATTACHED: u32 = 1 << 1;
pub const LINK_AT_NEW_BASE_ATTACHED: u32 = 1 << 2;
pub const LINK_AT_ROOT_ATTACHED: u32 = 1 << 3;
pub const LINK_AT_FLAGS_ALL: u32 = LINK_AT_FOLLOW_SOURCE
    | LINK_AT_OLD_BASE_ATTACHED
    | LINK_AT_NEW_BASE_ATTACHED
    | LINK_AT_ROOT_ATTACHED;

pub const TRUNCATE_AT_BASE_ATTACHED: u32 = 1 << 0;
pub const TRUNCATE_AT_ROOT_ATTACHED: u32 = 1 << 1;
/// For OP_TRUNCATE[_HANDLE/_AT], node_id carries an inclusive growth ceiling.
/// The filesystem checks current size and changes it in one serialized
/// operation. Shrinking or retaining an already-larger size remains allowed.
/// This is a per-operation bound, not a resource policy or credential.
pub const TRUNCATE_GROWTH_BOUNDED: u32 = 1 << 2;
pub const TRUNCATE_AT_FLAGS_ALL: u32 =
    TRUNCATE_AT_BASE_ATTACHED | TRUNCATE_AT_ROOT_ATTACHED | TRUNCATE_GROWTH_BOUNDED;
/// Non-errno operation failure. No mutation occurred because a supplied
/// growth ceiling was exceeded; the caller chooses its own policy response.
pub const ERROR_GROWTH_LIMIT: i32 = 0x10000;
/// Memory admission is temporarily busy BEFORE any namespace or storage
/// mutation. Retrying is safe; ordinary EAGAIN (including publication or
/// backend failures) does not carry this guarantee. Legacy replies have no
/// objects; requests using MUTATION_ADMISSION receive one WAIT|TRANSFER ticket.
pub const ERROR_MEMORY_ADMISSION_BUSY: i32 = 0x10002;

/// Opt in to nonblocking FIFO admission for OPEN_AT, TRUNCATE_HANDLE and
/// TRUNCATE_AT. The service never waits on the client's behalf. A busy reply
/// attaches exactly one WAIT|TRANSFER position, which the caller awaits and
/// explicitly attaches on the next attempt. No other error authorizes replay.
pub const MUTATION_ADMISSION: u32 = 1 << 31;
/// The final attachment is a borrowed admission ticket, after all ordinary
/// path anchors or the target FileHandle. Requires MUTATION_ADMISSION.
pub const MUTATION_ADMISSION_ATTACHED: u32 = 1 << 30;

pub const SYMLINK_AT_BASE_ATTACHED: u32 = 1 << 0;
pub const SYMLINK_AT_ROOT_ATTACHED: u32 = 1 << 1;
pub const SYMLINK_AT_FLAGS_ALL: u32 = SYMLINK_AT_BASE_ATTACHED | SYMLINK_AT_ROOT_ATTACHED;

pub const READLINK_AT_BASE_ATTACHED: u32 = 1 << 0;
pub const READLINK_AT_ROOT_ATTACHED: u32 = 1 << 1;
pub const READLINK_AT_FLAGS_ALL: u32 = READLINK_AT_BASE_ATTACHED | READLINK_AT_ROOT_ATTACHED;

pub const CHMOD_AT_BASE_ATTACHED: u32 = 1 << 0;
pub const CHMOD_AT_ROOT_ATTACHED: u32 = 1 << 1;
pub const CHMOD_AT_FLAGS_ALL: u32 = CHMOD_AT_BASE_ATTACHED | CHMOD_AT_ROOT_ATTACHED;

pub const CHOWN_AT_NOFOLLOW: u32 = 1 << 0;
pub const CHOWN_AT_BASE_ATTACHED: u32 = 1 << 1;
pub const CHOWN_AT_ROOT_ATTACHED: u32 = 1 << 2;
pub const CHOWN_AT_FLAGS_ALL: u32 =
    CHOWN_AT_NOFOLLOW | CHOWN_AT_BASE_ATTACHED | CHOWN_AT_ROOT_ATTACHED;

pub const SET_TIMES_AT_NOFOLLOW: u32 = 1 << 0;
pub const SET_TIMES_AT_BASE_ATTACHED: u32 = 1 << 1;
pub const SET_TIMES_AT_ROOT_ATTACHED: u32 = 1 << 2;
pub const SET_TIMES_AT_FLAGS_ALL: u32 =
    SET_TIMES_AT_NOFOLLOW | SET_TIMES_AT_BASE_ATTACHED | SET_TIMES_AT_ROOT_ATTACHED;

pub const SETATTR_MODE: u32 = 1 << 0;
pub const SETATTR_UID: u32 = 1 << 1;
pub const SETATTR_GID: u32 = 1 << 2;

/// Follow the final symbolic-link component during `OP_LOOKUP`.
pub const LOOKUP_FOLLOW_SYMLINKS: u32 = 1 << 0;

pub const OPEN_AT_READ: u32 = 1 << 0;
pub const OPEN_AT_WRITE: u32 = 1 << 1;
pub const OPEN_AT_CREATE: u32 = 1 << 2;
pub const OPEN_AT_EXCLUSIVE: u32 = 1 << 3;
pub const OPEN_AT_TRUNCATE: u32 = 1 << 4;
pub const OPEN_AT_APPEND: u32 = 1 << 5;
pub const OPEN_AT_DIRECTORY: u32 = 1 << 6;
pub const OPEN_AT_NOFOLLOW: u32 = 1 << 7;
pub const OPEN_AT_BASE_ATTACHED: u32 = 1 << 8;
pub const OPEN_AT_ROOT_ATTACHED: u32 = 1 << 9;
pub const OPEN_AT_NONBLOCK: u32 = 1 << 10;
/// Opens a directory for pathname traversal after checking search permission.
/// This is an internal filesystem-service operation, not a POSIX `open` flag.
pub const OPEN_AT_SEARCH: u32 = 1 << 11;
/// Request cursor-bearing records on a directory's provider stream. The
/// format is part of its open description and is shared by Handle aliases.
pub const OPEN_AT_CURSOR_RECORDS: u32 = 1 << 12;
pub const OPEN_AT_FLAGS_ALL: u32 = OPEN_AT_READ
    | OPEN_AT_WRITE
    | OPEN_AT_CREATE
    | OPEN_AT_EXCLUSIVE
    | OPEN_AT_TRUNCATE
    | OPEN_AT_APPEND
    | OPEN_AT_DIRECTORY
    | OPEN_AT_NOFOLLOW
    | OPEN_AT_BASE_ATTACHED
    | OPEN_AT_ROOT_ATTACHED
    | OPEN_AT_NONBLOCK
    | OPEN_AT_SEARCH
    | OPEN_AT_CURSOR_RECORDS;

pub const STAT_AT_NOFOLLOW: u32 = 1 << 0;
pub const STAT_AT_BASE_ATTACHED: u32 = 1 << 1;
pub const STAT_AT_ROOT_ATTACHED: u32 = 1 << 2;
pub const STAT_AT_FLAGS_ALL: u32 =
    STAT_AT_NOFOLLOW | STAT_AT_BASE_ATTACHED | STAT_AT_ROOT_ATTACHED;

pub const ACCESS_AT_READ: u32 = 1 << 2;
pub const ACCESS_AT_WRITE: u32 = 1 << 1;
pub const ACCESS_AT_EXECUTE: u32 = 1 << 0;
pub const ACCESS_AT_NOFOLLOW: u32 = 1 << 3;
pub const ACCESS_AT_BASE_ATTACHED: u32 = 1 << 4;
pub const ACCESS_AT_ROOT_ATTACHED: u32 = 1 << 5;
pub const ACCESS_AT_FLAGS_ALL: u32 = ACCESS_AT_READ
    | ACCESS_AT_WRITE
    | ACCESS_AT_EXECUTE
    | ACCESS_AT_NOFOLLOW
    | ACCESS_AT_BASE_ATTACHED
    | ACCESS_AT_ROOT_ATTACHED;

/// `Header::flags` carries the requested byte count for `OP_READ` and
/// `OP_READDIR`.
pub const MAX_IO_LEN: usize = MAX_MESSAGE_LEN - HEADER_LEN;
pub const DIRENT_HEADER_LEN: usize = 16;
/// A cursor-bearing record extends the legacy header with a provider-defined
/// continuation position. This is not a byte offset or a process-local FD.
pub const CURSOR_DIRENT_HEADER_LEN: usize = 24;
const DIRENT_HAS_CURSOR: u16 = 1;
pub const METADATA_LEN: usize = 8;
pub const NODE_STATUS_LEN: usize = 112;
pub const MAX_NAME_LEN: usize = 255;

pub const NODE_TYPE_REGULAR: u32 = 1;
pub const NODE_TYPE_DIRECTORY: u32 = 2;
pub const NODE_TYPE_SYMLINK: u32 = 3;
pub const NODE_TYPE_SPECIAL: u32 = 4;
pub const NODE_TYPE_SOCKET: u32 = 5;

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirEntryHeader {
    pub node_id: u64,
    pub kind: u32,
    pub name_len: u16,
    pub next_position: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NodeMetadata {
    pub uid: u32,
    pub gid: u32,
}

/// Architecture-independent credentials authenticated by a user-space policy
/// service before an atomic filesystem operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub effective_uid: u32,
    pub effective_gid: u32,
    supplementary_group_count: u32,
    supplementary_groups: [u32; MAX_SUPPLEMENTARY_GROUPS],
}

impl Credentials {
    pub const fn supplementary_groups(&self) -> &[u32] {
        self.supplementary_groups
            .split_at(self.supplementary_group_count as usize)
            .0
    }
}

/// Prefixes an operation payload with explicitly serialized credentials.
pub fn encode_credentials_payload(
    effective_uid: u32,
    effective_gid: u32,
    supplementary_groups: &[u32],
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    if supplementary_groups.len() > MAX_SUPPLEMENTARY_GROUPS {
        return Err(ProtocolError::InvalidLength);
    }
    let credentials_len = CREDENTIALS_HEADER_LEN
        .checked_add(
            supplementary_groups
                .len()
                .checked_mul(core::mem::size_of::<u32>())
                .ok_or(ProtocolError::InvalidLength)?,
        )
        .ok_or(ProtocolError::InvalidLength)?;
    let total = credentials_len
        .checked_add(payload.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if total > MAX_MESSAGE_LEN - HEADER_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, effective_uid);
    put_u32(output, 4, effective_gid);
    put_u32(output, 8, supplementary_groups.len() as u32);
    for (index, group) in supplementary_groups.iter().copied().enumerate() {
        put_u32(output, CREDENTIALS_HEADER_LEN + index * 4, group);
    }
    output[credentials_len..total].copy_from_slice(payload);
    Ok(total)
}

/// Decodes credentials and returns the remaining operation-specific payload.
pub fn decode_credentials_payload(input: &[u8]) -> Result<(Credentials, &[u8]), ProtocolError> {
    if input.len() < CREDENTIALS_HEADER_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let count = get_u32(input, 8) as usize;
    if count > MAX_SUPPLEMENTARY_GROUPS {
        return Err(ProtocolError::InvalidLength);
    }
    let credentials_len = CREDENTIALS_HEADER_LEN
        .checked_add(
            count
                .checked_mul(core::mem::size_of::<u32>())
                .ok_or(ProtocolError::InvalidLength)?,
        )
        .ok_or(ProtocolError::InvalidLength)?;
    if input.len() < credentials_len {
        return Err(ProtocolError::InvalidLength);
    }
    let mut supplementary_groups = [0u32; MAX_SUPPLEMENTARY_GROUPS];
    for (index, group) in supplementary_groups.iter_mut().take(count).enumerate() {
        *group = get_u32(input, CREDENTIALS_HEADER_LEN + index * 4);
    }
    Ok((
        Credentials {
            effective_uid: get_u32(input, 0),
            effective_gid: get_u32(input, 4),
            supplementary_group_count: count as u32,
            supplementary_groups,
        },
        &input[credentials_len..],
    ))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NodeStatus {
    pub device: u64,
    pub node_id: u64,
    pub size: u64,
    pub blocks: u64,
    pub block_size: u32,
    pub kind: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub link_count: u32,
    pub special_device: u64,
    /// Signed seconds since the Unix epoch, including pre-1970 timestamps.
    pub access_time_seconds: i64,
    pub access_time_nanoseconds: u32,
    pub modification_time_seconds: i64,
    pub modification_time_nanoseconds: u32,
    pub change_time_seconds: i64,
    pub change_time_nanoseconds: u32,
}

pub fn encode_node_status(
    status: NodeStatus,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    if output.len() < NODE_STATUS_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if !node_status_times_are_valid(&status) {
        return Err(ProtocolError::InvalidLength);
    }
    output[..NODE_STATUS_LEN].fill(0);
    put_u64(output, 0, status.device);
    put_u64(output, 8, status.node_id);
    put_u64(output, 16, status.size);
    put_u64(output, 24, status.blocks);
    put_u32(output, 32, status.block_size);
    put_u32(output, 36, status.kind);
    put_u32(output, 40, status.mode);
    put_u32(output, 44, status.uid);
    put_u32(output, 48, status.gid);
    put_u32(output, 52, status.link_count);
    put_u64(output, 56, status.special_device);
    put_u64(output, 64, status.access_time_seconds as u64);
    put_u32(output, 72, status.access_time_nanoseconds);
    put_u64(output, 80, status.modification_time_seconds as u64);
    put_u32(output, 88, status.modification_time_nanoseconds);
    put_u64(output, 96, status.change_time_seconds as u64);
    put_u32(output, 104, status.change_time_nanoseconds);
    Ok(NODE_STATUS_LEN)
}

pub fn decode_node_status(input: &[u8]) -> Result<NodeStatus, ProtocolError> {
    if input.len() != NODE_STATUS_LEN
        || input[76..80] != [0; 4]
        || input[92..96] != [0; 4]
        || input[108..112] != [0; 4]
    {
        return Err(ProtocolError::InvalidLength);
    }
    let status = NodeStatus {
        device: get_u64(input, 0),
        node_id: get_u64(input, 8),
        size: get_u64(input, 16),
        blocks: get_u64(input, 24),
        block_size: get_u32(input, 32),
        kind: get_u32(input, 36),
        mode: get_u32(input, 40),
        uid: get_u32(input, 44),
        gid: get_u32(input, 48),
        link_count: get_u32(input, 52),
        special_device: get_u64(input, 56),
        access_time_seconds: get_u64(input, 64) as i64,
        access_time_nanoseconds: get_u32(input, 72),
        modification_time_seconds: get_u64(input, 80) as i64,
        modification_time_nanoseconds: get_u32(input, 88),
        change_time_seconds: get_u64(input, 96) as i64,
        change_time_nanoseconds: get_u32(input, 104),
    };
    if !node_status_times_are_valid(&status) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(status)
}

fn node_status_times_are_valid(status: &NodeStatus) -> bool {
    [
        status.access_time_nanoseconds,
        status.modification_time_nanoseconds,
        status.change_time_nanoseconds,
    ]
    .into_iter()
    .all(|nanoseconds| nanoseconds < 1_000_000_000)
}

pub fn encode_metadata(
    metadata: NodeMetadata,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    if output.len() < METADATA_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, metadata.uid);
    put_u32(output, 4, metadata.gid);
    Ok(METADATA_LEN)
}

pub fn decode_metadata(input: &[u8]) -> Result<NodeMetadata, ProtocolError> {
    if input.len() != METADATA_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(NodeMetadata {
        uid: get_u32(input, 0),
        gid: get_u32(input, 4),
    })
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

pub fn encode_dir_entry(
    node_id: u64,
    kind: u32,
    name: &[u8],
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    encode_dir_entry_record(node_id, kind, name, None, output)
}

/// Encode the exact continuation token selected by the directory provider.
/// Hidden entries may make successive tokens non-consecutive. Clients must
/// not derive a token by counting the visible records or their byte lengths.
/// Readers must support the cursor extension before a producer enables it;
/// `encode_dir_entry` continues to emit the unchanged legacy format.
pub fn encode_cursor_dir_entry(
    node_id: u64,
    kind: u32,
    name: &[u8],
    next_position: u64,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    encode_dir_entry_record(node_id, kind, name, Some(next_position), output)
}

fn encode_dir_entry_record(
    node_id: u64,
    kind: u32,
    name: &[u8],
    next_position: Option<u64>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN || name.contains(&0) || name.contains(&b'/') {
        return Err(ProtocolError::InvalidLength);
    }
    let header_len = if next_position.is_some() {
        CURSOR_DIRENT_HEADER_LEN
    } else {
        DIRENT_HEADER_LEN
    };
    let total = header_len + name.len();
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..header_len].fill(0);
    put_u64(output, 0, node_id);
    put_u32(output, 8, kind);
    put_u16(output, 12, name.len() as u16);
    if let Some(position) = next_position {
        put_u16(output, 14, DIRENT_HAS_CURSOR);
        put_u64(output, DIRENT_HEADER_LEN, position);
    }
    output[header_len..total].copy_from_slice(name);
    Ok(total)
}

pub fn decode_dir_entry(input: &[u8]) -> Result<(DirEntryHeader, &[u8], usize), ProtocolError> {
    if input.len() < DIRENT_HEADER_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    let (header_len, has_cursor) = match get_u16(input, 14) {
        0 => (DIRENT_HEADER_LEN, false),
        DIRENT_HAS_CURSOR => (CURSOR_DIRENT_HEADER_LEN, true),
        _ => return Err(ProtocolError::UnsupportedVersion),
    };
    let name_len = get_u16(input, 12);
    if name_len == 0 || usize::from(name_len) > MAX_NAME_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let total = header_len
        .checked_add(usize::from(name_len))
        .ok_or(ProtocolError::InvalidLength)?;
    let name = input
        .get(header_len..total)
        .ok_or(ProtocolError::BufferTooSmall)?;
    if name.contains(&0) || name.contains(&b'/') {
        return Err(ProtocolError::InvalidLength);
    }
    Ok((
        DirEntryHeader {
            node_id: get_u64(input, 0),
            kind: get_u32(input, 8),
            name_len,
            next_position: if has_cursor {
                Some(get_u64(input, DIRENT_HEADER_LEN))
            } else {
                None
            },
        },
        name,
        total,
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

    #[test]
    fn directory_entry_round_trip() {
        let mut bytes = [0u8; 64];
        let length = encode_dir_entry(42, NODE_TYPE_DIRECTORY, b"Documents", &mut bytes).unwrap();
        let (header, name, consumed) = decode_dir_entry(&bytes[..length]).unwrap();
        assert_eq!(header.node_id, 42);
        assert_eq!(header.kind, NODE_TYPE_DIRECTORY);
        assert_eq!(header.name_len, 9);
        assert_eq!(name, b"Documents");
        assert_eq!(consumed, length);
    }

    #[test]
    fn metadata_round_trip() {
        let metadata = NodeMetadata { uid: 501, gid: 20 };
        let mut bytes = [0u8; METADATA_LEN];
        assert_eq!(encode_metadata(metadata, &mut bytes).unwrap(), METADATA_LEN);
        assert_eq!(decode_metadata(&bytes).unwrap(), metadata);
    }
}
