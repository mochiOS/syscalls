//! Atomic synchronous acceptance: provenance travels with the consumed signal.
use super::*;

pub const LEN: usize = 8 + signal_origin::LEN;
pub const TIMED_REQUEST_LEN: usize = SIGNAL_WAIT_REQUEST_LEN + 8;

pub fn encode_timed_request(
    mask: u64,
    epoch: u64,
    deadline: u64,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() < TIMED_REQUEST_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if deadline == u64::MAX {
        return Err(ProtocolError::InvalidLength);
    }
    encode_signal_wait_request(mask, epoch, output)?;
    put_u64(output, SIGNAL_WAIT_REQUEST_LEN, deadline);
    Ok(())
}

pub fn decode_timed_request(input: &[u8]) -> Result<(u64, u64, u64), ProtocolError> {
    if input.len() != TIMED_REQUEST_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let (mask, epoch) = decode_signal_wait_request(&input[..SIGNAL_WAIT_REQUEST_LEN])?;
    let deadline = get_u64(input, SIGNAL_WAIT_REQUEST_LEN);
    if deadline == u64::MAX {
        return Err(ProtocolError::InvalidLength);
    }
    Ok((mask, epoch, deadline))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub signal: u32,
    pub origin: signal_origin::Origin,
}

pub fn encode(value: Accepted, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if value.signal == 0
        || value.signal > SIGNAL_MAX
        || matches!(value.signal, SIGNAL_KILL | SIGNAL_STOP)
        || value.origin.source == signal_origin::FAULT
        || (value.origin.source == signal_origin::CHILD && value.signal != SIGNAL_CHLD)
    {
        return Err(ProtocolError::InvalidLength);
    }
    signal_origin::encode(value.origin, &mut output[8..LEN])?;
    put_u32(output, 0, value.signal);
    put_u32(output, 4, 0);
    Ok(())
}

pub fn decode(input: &[u8]) -> Result<Accepted, ProtocolError> {
    if input.len() != LEN || get_u32(input, 4) != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    let value = Accepted {
        signal: get_u32(input, 0),
        origin: signal_origin::decode(&input[8..])?,
    };
    encode(value, &mut [0; LEN])?;
    Ok(value)
}
