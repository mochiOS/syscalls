//! Open an external device through an attached factory and metadata reference.
//! Slot 0 is the scoped factory; slot 1 is the owned metadata-only reference.
//! No FD, path, object ID, or self-reported identity appears in the payload.
pub const MAGIC: [u8; 4] = *b"DVOP";
pub const VERSION: u16 = 1;
pub const REQUEST_LEN: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub rights: u64,
    pub options: u64,
}
impl Request {
    // Rights/options are interpreted and bounded by the resource owner, not
    // by a shared framing codec (and never by caller-reported credentials).
    pub fn encode(self) -> [u8; REQUEST_LEN] {
        let mut bytes = [0; REQUEST_LEN];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.rights.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.options.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, i32> {
        if bytes.len() != REQUEST_LEN
            || bytes[..4] != MAGIC
            || u16::from_le_bytes([bytes[4], bytes[5]]) != VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(-22);
        }
        Ok(Self {
            rights: u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| -22)?),
            options: u64::from_le_bytes(bytes[16..24].try_into().map_err(|_| -22)?),
        })
    }
}
