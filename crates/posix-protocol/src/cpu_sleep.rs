//! Process CPU sleep admission and one terminal completion record.
//! Process IDs select registered policy; no pointer or FD crosses this wire.
use crate::ProtocolError;

pub const REQUEST_LEN: usize = 32;
pub const REPLY_LEN: usize = 24;
pub const COMPLETION_LEN: usize = 8;
pub const COMPLETION_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WAIT;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// Zero selects the authenticated owner.
    pub process: u64,
    pub absolute: bool,
    pub nanoseconds: u128,
}

fn invalid() -> ProtocolError {
    ProtocolError::InvalidLength
}

pub fn encode_request(request: Request, out: &mut [u8]) -> Result<(), ProtocolError> {
    if request.process > crate::process_clock::MAX_PID
        || request.nanoseconds > crate::process_timer::MAX_DURATION_NS
    {
        return Err(invalid());
    }
    let out = out
        .get_mut(..REQUEST_LEN)
        .ok_or(ProtocolError::BufferTooSmall)?;
    out.fill(0);
    out[0] = 1;
    out[2] = u8::from(request.absolute);
    out[8..16].copy_from_slice(&request.process.to_le_bytes());
    out[16..32].copy_from_slice(&request.nanoseconds.to_le_bytes());
    Ok(())
}

pub fn decode_request(input: &[u8]) -> Result<Request, ProtocolError> {
    if input.len() != REQUEST_LEN || input[..2] != [1, 0] || input[2] > 1 || input[3..8] != [0; 5] {
        return Err(invalid());
    }
    let request = Request {
        process: u64::from_le_bytes(input[8..16].try_into().unwrap()),
        absolute: input[2] != 0,
        nanoseconds: u128::from_le_bytes(input[16..32].try_into().unwrap()),
    };
    if request.process > crate::process_clock::MAX_PID
        || request.nanoseconds > crate::process_timer::MAX_DURATION_NS
    {
        return Err(invalid());
    }
    Ok(request)
}

pub fn encode_reply(deadline: u128, out: &mut [u8]) -> Result<(), ProtocolError> {
    let out = out
        .get_mut(..REPLY_LEN)
        .ok_or(ProtocolError::BufferTooSmall)?;
    out.fill(0);
    out[0] = 1;
    out[8..24].copy_from_slice(&deadline.to_le_bytes());
    Ok(())
}

pub fn decode_reply(input: &[u8]) -> Result<u128, ProtocolError> {
    if input.len() != REPLY_LEN || input[..8] != [1, 0, 0, 0, 0, 0, 0, 0] {
        return Err(invalid());
    }
    Ok(u128::from_le_bytes(input[8..24].try_into().unwrap()))
}

pub fn encode_completion(result: Result<(), i32>, out: &mut [u8]) -> Result<(), ProtocolError> {
    let status = result.err().unwrap_or(0);
    if !(-4095..=0).contains(&status) {
        return Err(invalid());
    }
    let out = out
        .get_mut(..COMPLETION_LEN)
        .ok_or(ProtocolError::BufferTooSmall)?;
    out[..4].copy_from_slice(&[1, 0, 0, 0]);
    out[4..8].copy_from_slice(&status.to_le_bytes());
    Ok(())
}

pub fn decode_completion(input: &[u8]) -> Result<Result<(), i32>, ProtocolError> {
    if input.len() != COMPLETION_LEN || input[..4] != [1, 0, 0, 0] {
        return Err(invalid());
    }
    let status = i32::from_le_bytes(input[4..8].try_into().unwrap());
    if !(-4095..=0).contains(&status) {
        return Err(invalid());
    }
    Ok(if status == 0 { Ok(()) } else { Err(status) })
}
