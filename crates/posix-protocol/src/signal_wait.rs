//! Atomic synchronous acceptance: provenance travels with the consumed signal.
use super::*;

pub const LEN: usize = 8 + signal_origin::LEN;

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
