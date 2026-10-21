//! Elapsed-time timer wire values. No C pointers, native padding or timer IDs.
use crate::ProtocolError;

pub const LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum CpuClock {
    Virtual = 1,
    Profile = 2,
}

impl CpuClock {
    pub fn decode(input: &[u8]) -> Result<Self, ProtocolError> {
        match input {
            [1, 0, 0, 0] => Ok(Self::Virtual),
            [2, 0, 0, 0] => Ok(Self::Profile),
            _ => Err(ProtocolError::InvalidLength),
        }
    }
}

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
