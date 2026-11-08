//! Userspace pathname authority, authenticated by the POSIX controller. This
//! accompanies a single atomic provider operation, not a caller's path claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NamespacePolicy {
    pub read: u32,
    pub write: u32,
    /// Only explicit directory attachments, never the process cwd/root. A
    /// READ directory reference permits reading descendants, not mutation.
    pub explicit_read_bases: u32,
}
pub const ALL: u32 = 1;
pub const USER: u32 = 1 << 1;
pub const DOCUMENTS: u32 = 1 << 2;
pub const DOWNLOADS: u32 = 1 << 3;
pub const DESKTOP: u32 = 1 << 4;
pub const PICTURES: u32 = 1 << 5;
pub const MUSIC: u32 = 1 << 6;
pub const VIDEOS: u32 = 1 << 7;
pub const TMP: u32 = 1 << 8;
pub const REMOVABLE: u32 = 1 << 9;
pub const APPLICATIONS: u32 = 1 << 10;
pub const MASK: u32 = (1 << 11) - 1;
pub const LEN: usize = 12;
impl NamespacePolicy {
    pub const fn unrestricted() -> Self {
        Self {
            read: ALL,
            write: ALL,
            explicit_read_bases: 0,
        }
    }
    pub const fn denied() -> Self {
        Self {
            read: 0,
            write: 0,
            explicit_read_bases: 0,
        }
    }
    pub fn encode(self) -> [u8; LEN] {
        let mut bytes = [0; LEN];
        bytes[..4].copy_from_slice(&self.read.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.write.to_le_bytes());
        bytes[8..].copy_from_slice(&self.explicit_read_bases.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, crate::ProtocolError> {
        if bytes.len() != LEN {
            return Err(crate::ProtocolError::InvalidLength);
        }
        let value = Self {
            read: u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            write: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            explicit_read_bases: u32::from_le_bytes(bytes[8..].try_into().unwrap()),
        };
        if (value.read | value.write) & !MASK != 0 || value.explicit_read_bases & !3 != 0 {
            return Err(crate::ProtocolError::InvalidLength);
        }
        Ok(value)
    }
}
