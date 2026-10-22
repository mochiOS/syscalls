//! Open a fresh slave through an attached factory and metadata reference.
//! Slot 0 is the scoped factory; slot 1 is the owned metadata-only reference.
//! No FD, path, object ID, or self-reported identity appears in the payload.
pub const MAGIC: [u8; 4] = *b"PTYO";
pub const VERSION: u16 = 1;
pub const REQUEST_LEN: usize = 24;
pub const DATA_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_READ
    | mnu_abi::HANDLE_RIGHT_WRITE
    | mnu_abi::HANDLE_RIGHT_WAIT
    | mnu_abi::HANDLE_RIGHT_CONTROL
    | mnu_abi::HANDLE_RIGHT_DUPLICATE
    | mnu_abi::HANDLE_RIGHT_TRANSFER;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub rights: u64,
    pub options: u64,
}
impl Request {
    pub fn validate(self) -> Result<Self, i32> {
        if self.rights & !DATA_RIGHTS != 0
            || self.rights & mnu_abi::HANDLE_RIGHT_TRANSFER == 0
            || self.rights & (mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WRITE) == 0
            || self.options & !mnu_abi::HANDLE_OPTION_NONBLOCKING != 0
        {
            return Err(-22);
        }
        Ok(self)
    }
    pub fn encode(self) -> Result<[u8; REQUEST_LEN], i32> {
        self.validate()?;
        let mut bytes = [0; REQUEST_LEN];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.rights.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.options.to_le_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, i32> {
        if bytes.len() != REQUEST_LEN
            || bytes[..4] != MAGIC
            || u16::from_le_bytes([bytes[4], bytes[5]]) != VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(-22);
        }
        Self {
            rights: u64::from_le_bytes(bytes[8..16].try_into().map_err(|_| -22)?),
            options: u64::from_le_bytes(bytes[16..24].try_into().map_err(|_| -22)?),
        }
        .validate()
    }
}
