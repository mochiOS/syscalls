//! A generic immutable directory built from caller-owned bytes. This protocol
//! grants no pathname access and has no knowledge of packages or publishers.
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Creation request magic; the sole attachment is a readable anonymous object.
pub const MAGIC: [u8; 8] = *b"MFS1TREE";
/// Fixed request size: magic followed by the exact little-endian byte length.
pub const REQUEST_LEN: usize = 16;
/// Bound on one immutable tree's serialized data and metadata.
pub const MAX_BYTES: usize = 256 * 1024 * 1024;
/// Bound on explicit file entries; directories are derived, never symlinks.
pub const MAX_FILES: usize = 8192;
/// Bound on all files and derived directory nodes.
pub const MAX_NODES: usize = 32768;
/// Header preceding each UTF-8 name and file body: name length, reserved, size.
pub const ENTRY_LEN: usize = 16;

/// Validate a canonical, relative UTF-8 file name without ambient path syntax.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < super::MAX_PATH_LEN
        && !name.bytes().any(|b| b == b'\\' || b.is_ascii_control())
        && name
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != ".." && p.len() <= super::MAX_NAME_LEN)
}
/// Begin an empty version-one tree. Even an empty directory has a header.
#[cfg(feature = "alloc")]
pub fn begin() -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&0u64.to_le_bytes());
    out
}
/// Append an explicit file. Final structural validation belongs to the owner;
/// duplicate names and file/directory collisions must still be rejected there.
#[cfg(feature = "alloc")]
pub fn append(output: &mut Vec<u8>, name: &str, bytes: &[u8]) -> Result<(), ()> {
    if !valid_name(name) || output.len() < REQUEST_LEN || output[..8] != MAGIC {
        return Err(());
    }
    let count = u64::from_le_bytes(output[8..16].try_into().map_err(|_| ())?);
    let length = output
        .len()
        .checked_add(ENTRY_LEN)
        .and_then(|n| n.checked_add(name.len()))
        .and_then(|n| n.checked_add(bytes.len()))
        .ok_or(())?;
    if count >= MAX_FILES as u64 || length > MAX_BYTES {
        return Err(());
    }
    output.try_reserve(length - output.len()).map_err(|_| ())?;
    output.extend_from_slice(&(name.len() as u32).to_le_bytes());
    output.extend_from_slice(&0u32.to_le_bytes());
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(name.as_bytes());
    output.extend_from_slice(bytes);
    output[8..16].copy_from_slice(&(count + 1).to_le_bytes());
    Ok(())
}
/// Iterate validated record bounds without allocating file bodies. Callers must
/// finish iteration to reject trailing bytes or truncated declarations.
pub struct Entries<'a> {
    remaining: usize,
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Entries<'a> {
    /// Check the envelope and entry count before parsing any names or bodies.
    pub fn new(bytes: &'a [u8]) -> Result<Self, ()> {
        if bytes.len() < REQUEST_LEN || bytes.len() > MAX_BYTES || bytes[..8] != MAGIC {
            return Err(());
        }
        let count = usize::try_from(u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| ())?))
            .map_err(|_| ())?;
        if count > MAX_FILES {
            return Err(());
        }
        Ok(Self {
            remaining: count,
            bytes,
            offset: REQUEST_LEN,
        })
    }
    /// Return the logical name and its byte range within the captured object.
    pub fn next_entry(&mut self) -> Result<Option<(&'a str, core::ops::Range<usize>)>, ()> {
        if self.remaining == 0 {
            return if self.offset == self.bytes.len() {
                Ok(None)
            } else {
                Err(())
            };
        }
        let header_end = self.offset.checked_add(ENTRY_LEN).ok_or(())?;
        let h = self.bytes.get(self.offset..header_end).ok_or(())?;
        let name_len = u32::from_le_bytes(h[..4].try_into().map_err(|_| ())?) as usize;
        if h[4..8] != [0; 4] {
            return Err(());
        }
        let size = usize::try_from(u64::from_le_bytes(h[8..].try_into().map_err(|_| ())?))
            .map_err(|_| ())?;
        let name_end = header_end.checked_add(name_len).ok_or(())?;
        let end = name_end.checked_add(size).ok_or(())?;
        let name = core::str::from_utf8(self.bytes.get(header_end..name_end).ok_or(())?)
            .map_err(|_| ())?;
        if !valid_name(name) || end > self.bytes.len() {
            return Err(());
        }
        self.remaining -= 1;
        self.offset = end;
        Ok(Some((name, name_end..end)))
    }
}
