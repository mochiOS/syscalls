//! Datagram backend wire. Native Handle attachments carry authority; these
//! bytes contain only endpoints and packet data, never client FD/PID/object IDs.
use super::datagram_authority::Error;
pub const OPEN_OPCODE: u16 = 2;
pub const ENDPOINT_LEN: usize = 8;
pub const RECEIVE_HEADER_LEN: usize = 12;
pub const MAX_PAYLOAD: usize = 1472;
pub const TAKE_STATUS: u64 = u64::from_le_bytes(*b"NUDPERR1");
pub const LOCAL: u64 = u64::from_le_bytes(*b"NUDPLOC1");
pub const PEER: u64 = u64::from_le_bytes(*b"NUDPPEE1");
pub const SET_PEER: u64 = u64::from_le_bytes(*b"NUDPSET1");
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub address: [u8; 4],
    pub port: u16,
}
impl Endpoint {
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < ENDPOINT_LEN {
            return Err(Error::Invalid);
        }
        out[..8].fill(0);
        out[..4].copy_from_slice(&self.address);
        out[4..6].copy_from_slice(&self.port.to_le_bytes());
        Ok(8)
    }
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() != 8 || input[6..8] != [0; 2] {
            return Err(Error::Invalid);
        }
        Ok(Self {
            address: input[..4].try_into().unwrap(),
            port: u16::from_le_bytes(input[4..6].try_into().unwrap()),
        })
    }
    pub fn unspecified(self) -> bool {
        self.address == [0; 4] && self.port == 0
    }
}
pub fn open(local: Endpoint, out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < 16 {
        return Err(Error::Invalid);
    }
    out[..8].copy_from_slice(&[b'N', b'U', b'D', b'P', 1, 0, 2, 0]);
    local.encode(&mut out[8..16])?;
    Ok(16)
}
pub fn decode_open(input: &[u8]) -> Result<Endpoint, Error> {
    if input.len() != 16 || input[..8] != [b'N', b'U', b'D', b'P', 1, 0, 2, 0] {
        return Err(Error::Invalid);
    }
    Endpoint::decode(&input[8..])
}
pub fn send(destination: Option<Endpoint>, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if payload.len() > MAX_PAYLOAD || out.len() < 8 + payload.len() {
        return Err(Error::Invalid);
    }
    destination
        .unwrap_or(Endpoint {
            address: [0; 4],
            port: 0,
        })
        .encode(&mut out[..8])?;
    out[8..8 + payload.len()].copy_from_slice(payload);
    Ok(8 + payload.len())
}
pub fn decode_send(input: &[u8]) -> Result<(Option<Endpoint>, &[u8]), Error> {
    if input.len() < 8 || input.len() > 8 + MAX_PAYLOAD {
        return Err(Error::Invalid);
    }
    let endpoint = Endpoint::decode(&input[..8])?;
    Ok((
        if endpoint.unspecified() {
            None
        } else {
            Some(endpoint)
        },
        &input[8..],
    ))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Received<'a> {
    pub source: Endpoint,
    pub original_length: usize,
    pub payload: &'a [u8],
}
impl Received<'_> {
    pub fn truncated(&self) -> bool {
        self.payload.len() < self.original_length
    }
}
pub fn received(source: Endpoint, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < RECEIVE_HEADER_LEN || payload.len() > MAX_PAYLOAD {
        return Err(Error::Invalid);
    }
    let copied = payload.len().min(out.len() - RECEIVE_HEADER_LEN);
    source.encode(&mut out[..8])?;
    out[6..8].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    out[8..12].copy_from_slice(&u32::from(copied < payload.len()).to_le_bytes());
    out[12..12 + copied].copy_from_slice(&payload[..copied]);
    Ok(12 + copied)
}
pub fn decode_received(input: &[u8]) -> Result<Received<'_>, Error> {
    if input.len() < RECEIVE_HEADER_LEN {
        return Err(Error::Invalid);
    }
    let original_length = u16::from_le_bytes(input[6..8].try_into().unwrap()) as usize;
    let flags = u32::from_le_bytes(input[8..12].try_into().unwrap());
    if original_length > MAX_PAYLOAD
        || input.len() - 12 > original_length
        || flags != u32::from(input.len() - 12 < original_length)
    {
        return Err(Error::Invalid);
    }
    Ok(Received {
        source: Endpoint {
            address: input[..4].try_into().unwrap(),
            port: u16::from_le_bytes(input[4..6].try_into().unwrap()),
        },
        original_length,
        payload: &input[12..],
    })
}
