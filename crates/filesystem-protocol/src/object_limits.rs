//! Limits reported by the filesystem owning a retained description.
//! Selectors and payloads are opaque to the kernel; no libc name numbers cross
//! this interface. Byte limits exclude any C string terminator.

/// Empty input, exactly RESPONSE_LEN bytes of output. READ query, or an
/// explicitly supported CONTROL observation for a write-only description.
pub const GET: u64 = u64::from_le_bytes(*b"MFS1LIMT");
pub const RESPONSE_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub name_bytes_max: u32,
    pub path_bytes_max: u32,
    pub link_count_max: u32,
    /// The selected volume's allocation block size, not a claim that every
    /// object consumes at least one block or supports direct I/O.
    pub filesystem_block_bytes: u32,
}

impl Limits {
    pub fn encode(self) -> [u8; RESPONSE_LEN] {
        let mut bytes = [0; RESPONSE_LEN];
        for (slot, value) in bytes.chunks_exact_mut(4).zip([
            self.name_bytes_max,
            self.path_bytes_max,
            self.link_count_max,
            self.filesystem_block_bytes,
        ]) {
            slot.copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; RESPONSE_LEN] = bytes.try_into().ok()?;
        Some(Self {
            name_bytes_max: u32::from_le_bytes(bytes[0..4].try_into().ok()?),
            path_bytes_max: u32::from_le_bytes(bytes[4..8].try_into().ok()?),
            link_count_max: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
            filesystem_block_bytes: u32::from_le_bytes(bytes[12..16].try_into().ok()?),
        })
    }
}
