//! TCP resource protocol. Authority and references are native IPC attachments;
//! no PID, FD or provider-owned identifier appears in these messages.
pub use super::datagram::{ENDPOINT_LEN, Endpoint};
pub const ACQUIRE: u16 = 1;
pub const OPEN: u16 = 2;
pub const ACCEPT: u16 = 3;
pub const VALIDATE: u16 = 4;
pub const DERIVE: u16 = 5;
pub const CONNECT_SCOPE: u32 = 1;
pub const LISTEN_SCOPE: u32 = 2;
pub const ALL_SCOPES: u32 = CONNECT_SCOPE | LISTEN_SCOPE;
pub const REPLY_LEN: usize = 16;
pub const LIMITS_LEN: usize = 12;
pub const ROUTE_LOOPBACK: u16 = 1;
pub const ROUTE_INTERFACE: u16 = 2;
pub const STATUS_LEN: usize = 8;
pub const QUERY_LIMITS: u64 = u64::from_le_bytes(*b"NTCPLIM1");
pub const LOCAL: u64 = u64::from_le_bytes(*b"NTCPLOC1");
pub const PEER: u64 = u64::from_le_bytes(*b"NTCPPEE1");
pub const STATUS: u64 = u64::from_le_bytes(*b"NTCPSTA1");
pub const TAKE_ERROR: u64 = u64::from_le_bytes(*b"NTCPERR1");
pub const BIND: u64 = u64::from_le_bytes(*b"NTCPBND1");
pub const CONNECT: u64 = u64::from_le_bytes(*b"NTCPCON1");
pub const LISTEN: u64 = u64::from_le_bytes(*b"NTCPLSN1");
pub const SHUTDOWN: u64 = u64::from_le_bytes(*b"NTCPSHT1");
/// Empty input, u32 result: 0 aborted an uncommitted open; 1 the
/// connection already committed and was preserved. Errors retain their cause.
pub const CANCEL_CONNECT: u64 = u64::from_le_bytes(*b"NTCPCAN1");
pub const READABLE: u32 = 1;
pub const WRITABLE: u32 = 2;
pub const PEER_CLOSED: u32 = 4;
pub const CONNECTING: u32 = 8;
pub const READ_SHUTDOWN: u32 = 1;
pub const WRITE_SHUTDOWN: u32 = 2;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
}
pub fn header(operation: u16) -> [u8; 8] {
    let [a, b] = operation.to_le_bytes();
    [b'N', b'T', b'C', b'P', 1, 0, a, b]
}
pub fn operation(bytes: &[u8]) -> Result<u16, Error> {
    if bytes.len() < 8 || bytes[..6] != [b'N', b'T', b'C', b'P', 1, 0] {
        return Err(Error::Invalid);
    }
    Ok(u16::from_le_bytes([bytes[6], bytes[7]]))
}
pub fn scoped(operation: u16, scopes: u32) -> Result<[u8; 12], Error> {
    if !matches!(operation, ACQUIRE | DERIVE) || scopes == 0 || scopes & !ALL_SCOPES != 0 {
        return Err(Error::Invalid);
    }
    let mut bytes = [0; 12];
    bytes[..8].copy_from_slice(&header(operation));
    bytes[8..].copy_from_slice(&scopes.to_le_bytes());
    Ok(bytes)
}
pub fn scopes(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.len() != 12 || !matches!(operation(bytes)?, ACQUIRE | DERIVE) {
        return Err(Error::Invalid);
    }
    let scopes = u32::from_le_bytes(bytes[8..].try_into().unwrap());
    if scopes == 0 || scopes & !ALL_SCOPES != 0 {
        return Err(Error::Invalid);
    }
    Ok(scopes)
}
pub fn reply(operation: u16, status: i32, out: &mut [u8]) -> Result<usize, Error> {
    if status > 0 || out.len() < REPLY_LEN {
        return Err(Error::Invalid);
    }
    out[..REPLY_LEN].fill(0);
    out[..8].copy_from_slice(&header(operation));
    out[3] = b'R';
    out[8..12].copy_from_slice(&status.to_le_bytes());
    Ok(REPLY_LEN)
}
pub fn status(operation: u16, bytes: &[u8]) -> Result<i32, Error> {
    let mut expected = header(operation);
    expected[3] = b'R';
    if bytes.len() != REPLY_LEN || bytes[..8] != expected || bytes[12..] != [0; 4] {
        return Err(Error::Invalid);
    }
    let status = i32::from_le_bytes(bytes[8..12].try_into().unwrap());
    if status > 0 {
        return Err(Error::Invalid);
    }
    Ok(status)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub scopes: u32,
    pub minimum_port: u16,
    pub routes: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub flags: u32,
    pub error: i32,
}
impl Observation {
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < STATUS_LEN
            || self.flags & !(READABLE | WRITABLE | PEER_CLOSED | CONNECTING) != 0
            || self.error > 0
        {
            return Err(Error::Invalid);
        }
        out[..4].copy_from_slice(&self.flags.to_le_bytes());
        out[4..8].copy_from_slice(&self.error.to_le_bytes());
        Ok(STATUS_LEN)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != STATUS_LEN {
            return Err(Error::Invalid);
        }
        let value = Self {
            flags: u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            error: i32::from_le_bytes(bytes[4..].try_into().unwrap()),
        };
        value.encode(&mut [0; STATUS_LEN])?;
        Ok(value)
    }
}
impl Limits {
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        if self.scopes == 0
            || self.scopes & !ALL_SCOPES != 0
            || self.minimum_port == 0
            || self.routes & ROUTE_LOOPBACK == 0
            || self.routes & !(ROUTE_LOOPBACK | ROUTE_INTERFACE) != 0
            || out.len() < LIMITS_LEN
        {
            return Err(Error::Invalid);
        }
        out[..LIMITS_LEN].fill(0);
        out[..2].copy_from_slice(&1u16.to_le_bytes());
        out[2..4].copy_from_slice(&self.routes.to_le_bytes());
        out[4..8].copy_from_slice(&self.scopes.to_le_bytes());
        out[8..10].copy_from_slice(&self.minimum_port.to_le_bytes());
        Ok(LIMITS_LEN)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != LIMITS_LEN || bytes[..2] != [1, 0] || bytes[10..] != [0; 2] {
            return Err(Error::Invalid);
        }
        let value = Self {
            scopes: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            minimum_port: u16::from_le_bytes(bytes[8..10].try_into().unwrap()),
            routes: u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
        };
        let mut checked = [0; LIMITS_LEN];
        value.encode(&mut checked)?;
        Ok(value)
    }
}
