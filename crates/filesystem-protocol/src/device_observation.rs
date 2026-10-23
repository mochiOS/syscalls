//! Read-only device metadata through exactly one attached factory grant.
//! No data open, pathname, FD, provider ID or claimed identity is encoded.
pub const MAGIC: [u8; 4] = *b"DVOB";
pub const VERSION: u16 = 1;
pub const REQUEST_LEN: usize = 24;
pub const MAX_RESPONSE_LEN: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub selector: u64,
    pub capacity: u32,
}

impl Request {
    pub fn encode(self) -> [u8; REQUEST_LEN] {
        let mut bytes = [0; REQUEST_LEN];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.selector.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.capacity.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, i32> {
        if bytes.len() != REQUEST_LEN
            || bytes[..4] != MAGIC
            || bytes[4..6] != VERSION.to_le_bytes()
            || bytes[6..8] != [0; 2]
            || bytes[20..24] != [0; 4]
        {
            return Err(-22);
        }
        let request = Self {
            selector: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            capacity: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
        };
        if request.capacity as usize > MAX_RESPONSE_LEN {
            return Err(-22);
        }
        Ok(request)
    }
}
