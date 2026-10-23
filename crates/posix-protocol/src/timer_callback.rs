//! Callback delivery carries registry cookies only. Executable addresses,
//! sigval bits and pthread attributes remain in the receiving process.
use crate::ProtocolError;

pub const REQUEST_LEN: usize = 8;
pub const REPLY_LEN: usize = 32;
pub const REQUEST: [u8; REQUEST_LEN] = [1, 0, 0, 0, 0, 0, 0, 0];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub timer: u64,
    pub cookie: u64,
    pub overrun: u32,
}

pub fn decode_request(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes != REQUEST {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(())
}

pub fn encode(event: Event, bytes: &mut [u8]) -> Result<(), ProtocolError> {
    if event.timer == 0 || event.cookie == 0 || event.overrun > i32::MAX as u32 {
        return Err(ProtocolError::InvalidLength);
    }
    let bytes = bytes
        .get_mut(..REPLY_LEN)
        .ok_or(ProtocolError::BufferTooSmall)?;
    bytes.fill(0);
    bytes[..REQUEST_LEN].copy_from_slice(&REQUEST);
    bytes[8..16].copy_from_slice(&event.timer.to_le_bytes());
    bytes[16..24].copy_from_slice(&event.cookie.to_le_bytes());
    bytes[24..28].copy_from_slice(&event.overrun.to_le_bytes());
    Ok(())
}

pub fn decode(bytes: &[u8]) -> Result<Event, ProtocolError> {
    if bytes.len() != REPLY_LEN || bytes[..8] != REQUEST || bytes[28..] != [0; 4] {
        return Err(ProtocolError::InvalidLength);
    }
    let event = Event {
        timer: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        cookie: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        overrun: u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
    };
    encode(event, &mut [0; REPLY_LEN])?;
    Ok(event)
}
