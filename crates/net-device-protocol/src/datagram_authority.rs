//! Authority acquisition for the datagram backend. Object identity and resource
//! authority travel only as native Handle attachments, never as wire integers.
pub const ACQUIRE: [u8; 8] = [b'N', b'U', b'D', b'P', 1, 0, 1, 0];
pub const VALIDATE: [u8; 8] = [b'N', b'U', b'D', b'P', 1, 0, 3, 0];
pub const REPLY_LEN: usize = 16;
pub const LIMITS_LEN: usize = 12;
pub const QUERY_LIMITS: u64 = u64::from_le_bytes(*b"NUDPLIM1");
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
}
pub fn reply(status: i32, output: &mut [u8]) -> Result<usize, Error> {
    reply_for(1, status, output)
}
pub fn reply_for(operation: u16, status: i32, output: &mut [u8]) -> Result<usize, Error> {
    if output.len() < REPLY_LEN || status > 0 {
        return Err(Error::Invalid);
    }
    output[..REPLY_LEN].fill(0);
    output[..8].copy_from_slice(&[b'N', b'U', b'D', b'R', 1, 0, 1, 0]);
    output[6..8].copy_from_slice(&operation.to_le_bytes());
    output[8..12].copy_from_slice(&status.to_le_bytes());
    Ok(REPLY_LEN)
}
pub fn status(input: &[u8]) -> Result<i32, Error> {
    status_for(1, input)
}
pub fn status_for(operation: u16, input: &[u8]) -> Result<i32, Error> {
    if input.len() != REPLY_LEN
        || input[..6] != [b'N', b'U', b'D', b'R', 1, 0]
        || input[6..8] != operation.to_le_bytes()
        || input[12..16] != [0; 4]
    {
        return Err(Error::Invalid);
    }
    let status = i32::from_le_bytes(input[8..12].try_into().unwrap());
    if status > 0 {
        return Err(Error::Invalid);
    }
    Ok(status)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub minimum_port: u16,
    pub maximum_payload: u16,
}
impl Limits {
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < LIMITS_LEN || self.minimum_port == 0 || self.maximum_payload == 0 {
            return Err(Error::Invalid);
        }
        output[..LIMITS_LEN].fill(0);
        output[..4].copy_from_slice(&[1, 0, 1, 0]); // version, IPv4 backend tag
        output[4..6].copy_from_slice(&self.minimum_port.to_le_bytes());
        output[6..8].copy_from_slice(&self.maximum_payload.to_le_bytes());
        Ok(LIMITS_LEN)
    }
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() != LIMITS_LEN || input[..4] != [1, 0, 1, 0] || input[8..12] != [0; 4] {
            return Err(Error::Invalid);
        }
        let value = Self {
            minimum_port: u16::from_le_bytes(input[4..6].try_into().unwrap()),
            maximum_payload: u16::from_le_bytes(input[6..8].try_into().unwrap()),
        };
        if value.minimum_port == 0 || value.maximum_payload == 0 {
            return Err(Error::Invalid);
        }
        Ok(value)
    }
}
