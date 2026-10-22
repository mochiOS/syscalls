//! A data provider returns its associated filesystem metadata reference only
//! for an explicitly attached native data Handle. No object IDs are inline.
pub const MAGIC: [u8; 4] = *b"DVMT";
pub const VERSION: u16 = 1;
pub const REQUEST_LEN: usize = 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub rights: u64,
}
impl Request {
    pub fn encode(self) -> [u8; REQUEST_LEN] {
        let mut bytes = [0; REQUEST_LEN];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.rights.to_le_bytes());
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
        })
    }
}
