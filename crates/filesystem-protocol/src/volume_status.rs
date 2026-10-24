//! Live volume accounting. Native selectors and bytes remain opaque to mnu.
pub const GET: u64 = u64::from_le_bytes(*b"MFS1VSTA");
pub const RESPONSE_LEN: usize = 56;
pub const READ_ONLY: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    /// Allocation unit used by every block counter below.
    pub block_bytes: u32,
    pub flags: u32,
    pub blocks: u64,
    pub free_blocks: u64,
    pub inodes: u64,
    pub free_inodes: u64,
    /// The owner's mounted-volume identity, never authority to that volume.
    pub filesystem_id: u64,
    pub name_bytes_max: u32,
}

impl Status {
    pub fn encode(self) -> [u8; RESPONSE_LEN] {
        let mut bytes = [0; RESPONSE_LEN];
        bytes[..4].copy_from_slice(&self.block_bytes.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.flags.to_le_bytes());
        for (slot, value) in bytes[8..48].chunks_exact_mut(8).zip([
            self.blocks,
            self.free_blocks,
            self.inodes,
            self.free_inodes,
            self.filesystem_id,
        ]) {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        bytes[48..52].copy_from_slice(&self.name_bytes_max.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; RESPONSE_LEN] = bytes.try_into().ok()?;
        if bytes[52..] != [0; 4] {
            return None;
        }
        let u64_at = |offset| {
            Some(u64::from_le_bytes(
                bytes.get(offset..offset + 8)?.try_into().ok()?,
            ))
        };
        let status = Self {
            block_bytes: u32::from_le_bytes(bytes[..4].try_into().ok()?),
            flags: u32::from_le_bytes(bytes[4..8].try_into().ok()?),
            blocks: u64_at(8)?,
            free_blocks: u64_at(16)?,
            inodes: u64_at(24)?,
            free_inodes: u64_at(32)?,
            filesystem_id: u64_at(40)?,
            name_bytes_max: u32::from_le_bytes(bytes[48..52].try_into().ok()?),
        };
        (status.block_bytes != 0
            && status.name_bytes_max != 0
            && status.flags & !READ_ONLY == 0
            && status.free_blocks <= status.blocks
            && status.free_inodes <= status.inodes)
            .then_some(status)
    }
}
