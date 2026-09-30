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
pub const OP_SETATTR: u16 = 17;
pub const OP_STATUS: u16 = 0x8000;

pub const SETATTR_MODE: u32 = 1 << 0;
pub const SETATTR_UID: u32 = 1 << 1;
pub const SETATTR_GID: u32 = 1 << 2;

/// Follow the final symbolic-link component during `OP_LOOKUP`.
pub const LOOKUP_FOLLOW_SYMLINKS: u32 = 1 << 0;

/// Registers an IPC endpoint as an opaque filesystem provider.
pub const SYS_FILESYSTEM_REGISTER: u64 = 621;
/// Mounts a registered filesystem provider at a caller-supplied path.
pub const SYS_FILESYSTEM_MOUNT: u64 = 622;

/// `Header::flags` carries the requested byte count for `OP_READ` and
/// `OP_READDIR`.
pub const MAX_IO_LEN: usize = MAX_MESSAGE_LEN - HEADER_LEN;
pub const DIRENT_HEADER_LEN: usize = 16;
pub const METADATA_LEN: usize = 8;
pub const MAX_NAME_LEN: usize = 255;

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DirEntryHeader {
    pub node_id: u64,
    pub kind: u32,
    pub name_len: u16,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NodeMetadata {
    pub uid: u32,
    pub gid: u32,
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
    if name.is_empty() || name.len() > MAX_NAME_LEN || name.contains(&0) || name.contains(&b'/') {
        return Err(ProtocolError::InvalidLength);
    }
    let total = DIRENT_HEADER_LEN + name.len();
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..DIRENT_HEADER_LEN].fill(0);
    put_u64(output, 0, node_id);
    put_u32(output, 8, kind);
    put_u16(output, 12, name.len() as u16);
    output[DIRENT_HEADER_LEN..total].copy_from_slice(name);
    Ok(total)
}

pub fn decode_dir_entry(input: &[u8]) -> Result<(DirEntryHeader, &[u8], usize), ProtocolError> {
    if input.len() < DIRENT_HEADER_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    let name_len = get_u16(input, 12);
    if name_len == 0 || usize::from(name_len) > MAX_NAME_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let total = DIRENT_HEADER_LEN
        .checked_add(usize::from(name_len))
        .ok_or(ProtocolError::InvalidLength)?;
    let name = input
        .get(DIRENT_HEADER_LEN..total)
        .ok_or(ProtocolError::BufferTooSmall)?;
    if name.contains(&0) || name.contains(&b'/') {
        return Err(ProtocolError::InvalidLength);
    }
    Ok((
        DirEntryHeader {
            node_id: get_u64(input, 0),
            kind: get_u32(input, 8),
            name_len,
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
