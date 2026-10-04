use core::str::Utf8Error;

use mochios_filesystem_protocol as filesystem;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectoryEntry<'a> {
    pub object_id: u64,
    pub kind: u32,
    pub name: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectoryDecodeError {
    Protocol(filesystem::ProtocolError),
    InvalidName(Utf8Error),
}

/// Decodes one chunk returned by `HandleRead` on a directory object.
///
/// filesystem.service never splits a record across HandleRead responses, so
/// each chunk can be consumed independently without process-global state.
pub struct DirectoryEntries<'a> {
    remaining: &'a [u8],
}

impl<'a> DirectoryEntries<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
}

impl<'a> Iterator for DirectoryEntries<'a> {
    type Item = Result<DirectoryEntry<'a>, DirectoryDecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let (header, name, consumed) = match filesystem::decode_dir_entry(self.remaining) {
            Ok(record) => record,
            Err(error) => {
                self.remaining = &[];
                return Some(Err(DirectoryDecodeError::Protocol(error)));
            }
        };
        self.remaining = &self.remaining[consumed..];
        let name = match core::str::from_utf8(name) {
            Ok(name) => name,
            Err(error) => return Some(Err(DirectoryDecodeError::InvalidName(error))),
        };
        Some(Ok(DirectoryEntry {
            object_id: header.node_id,
            kind: header.kind,
            name,
        }))
    }
}
