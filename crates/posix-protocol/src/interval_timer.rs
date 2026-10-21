//! Elapsed-time timer wire values. No C pointers, native padding or timer IDs.
use crate::ProtocolError;

pub const LEN: usize = 16;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Value {
    pub interval_ns: u64,
    pub remaining_ns: u64,
}

pub fn encode(value: Value, output: &mut [u8]) -> Result<(), ProtocolError> {
    let output = output.get_mut(..LEN).ok_or(ProtocolError::BufferTooSmall)?;
    output[..8].copy_from_slice(&value.interval_ns.to_le_bytes());
    output[8..].copy_from_slice(&value.remaining_ns.to_le_bytes());
    Ok(())
}

pub fn decode(input: &[u8]) -> Result<Value, ProtocolError> {
    if input.len() != LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(Value {
        interval_ns: u64::from_le_bytes(input[..8].try_into().unwrap()),
        remaining_ns: u64::from_le_bytes(input[8..].try_into().unwrap()),
    })
}
