//! Explicit startup bundle authority. Alias/path text selects within a native
//! token; neither package identities nor physical paths are accepted as grants.
/// Ordinary IPC opcode for a request carrying exactly one bundle token.
pub const OPCODE: u32 = u32::from_le_bytes(*b"BND1");
/// Native startup key for the selected executable's resource authority.
pub const ROOT_KEY: u64 = u64::from_le_bytes(*b"MBNDROOT");
/// Native startup key for the broker endpoint; has no kernel policy meaning.
pub const CONTROL_KEY: u64 = u64::from_le_bytes(*b"MBNDCTRL");
/// Check a selected alias without opening or capturing data.
pub const CHECK: u16 = 0;
/// Return a read-only regular file.
pub const OPEN: u16 = 1;
/// Return a read-only directory containing exactly the selected set.
pub const DIRECTORY: u16 = 2;
/// Fixed header length before UTF-8 alias and logical file name.
pub const HEADER_LEN: usize = 12;
/// Largest request; bounded by the control service's inline receive buffer.
pub const MAX_BYTES: usize = HEADER_LEN + 128 + 4095;
/// Decoded selection. Empty alias denotes the launching application's assets.
pub struct Request<'a> {
    pub operation: u16,
    pub alias: &'a str,
    pub name: &'a str,
}
fn valid_component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 255
        && !name
            .bytes()
            .any(|b| b == b'/' || b == b'\\' || b.is_ascii_control())
}
impl Request<'_> {
    /// Validate only syntax, never authority; the broker must verify the token.
    pub fn valid(&self) -> bool {
        (self.alias.is_empty() || (self.alias.len() <= 128 && valid_component(self.alias)))
            && match self.operation {
                CHECK | DIRECTORY => self.name.is_empty(),
                OPEN => {
                    !self.name.is_empty()
                        && self.name.len() <= 4095
                        && self.name.split('/').all(valid_component)
                }
                _ => false,
            }
    }
    /// Encode a bounded request with zero reserved bytes.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, ()> {
        if !self.valid() {
            return Err(());
        }
        let n = HEADER_LEN + self.alias.len() + self.name.len();
        if output.len() < n {
            return Err(());
        }
        output[..4].copy_from_slice(&OPCODE.to_le_bytes());
        output[4..6].copy_from_slice(&self.operation.to_le_bytes());
        output[6..8].fill(0);
        output[8..10].copy_from_slice(&(self.alias.len() as u16).to_le_bytes());
        output[10..12].copy_from_slice(&(self.name.len() as u16).to_le_bytes());
        output[12..12 + self.alias.len()].copy_from_slice(self.alias.as_bytes());
        output[12 + self.alias.len()..n].copy_from_slice(self.name.as_bytes());
        Ok(n)
    }
}
/// Decode exact lengths; unknown operations/flags and trailing data are rejected.
pub fn decode(bytes: &[u8]) -> Result<Request<'_>, ()> {
    if bytes.len() < HEADER_LEN
        || bytes.len() > MAX_BYTES
        || bytes[..4] != OPCODE.to_le_bytes()
        || bytes[6..8] != [0; 2]
    {
        return Err(());
    }
    let a = u16::from_le_bytes(bytes[8..10].try_into().map_err(|_| ())?) as usize;
    let n = u16::from_le_bytes(bytes[10..12].try_into().map_err(|_| ())?) as usize;
    if HEADER_LEN + a + n != bytes.len() {
        return Err(());
    }
    let request = Request {
        operation: u16::from_le_bytes(bytes[4..6].try_into().map_err(|_| ())?),
        alias: core::str::from_utf8(&bytes[12..12 + a]).map_err(|_| ())?,
        name: core::str::from_utf8(&bytes[12 + a..]).map_err(|_| ())?,
    };
    if !request.valid() {
        return Err(());
    }
    Ok(request)
}
