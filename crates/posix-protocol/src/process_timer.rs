//! Canonical per-process timer control frames. Ownership comes from IPC
//! metadata, never a PID, FD, function pointer, or native clock selector here.
use crate::ProtocolError;

pub const CREATE_LEN: usize = 24;
pub const VALUE_LEN: usize = 32;
pub const SET_LEN: usize = 48;
pub const MAX_DURATION_NS: u128 = i64::MAX as u128 * 1_000_000_000 + 999_999_999;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Clock {
    Realtime = 1,
    Monotonic = 2,
    ProcessCpu = 3,
    /// CPU clock of the creating IPC thread, or of one attached WAIT Thread
    /// Handle. No identity or Handle selector is encoded in the frame.
    ThreadCpu = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notification {
    None,
    Default,
    Signal {
        signal: u32,
        /// Opaque process-local value registry token. Original sigval pointer
        /// bits stay in the requesting process, not in this wire record.
        value: u64,
    },
    /// Process-local callback registry cookie, not an executable address.
    Thread {
        cookie: u64,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Value {
    pub remaining_ns: u128,
    pub interval_ns: u128,
}

fn invalid() -> ProtocolError {
    ProtocolError::InvalidLength
}

pub fn encode_create(
    clock: Clock,
    notification: Notification,
    out: &mut [u8],
) -> Result<(), ProtocolError> {
    let out = out
        .get_mut(..CREATE_LEN)
        .ok_or(ProtocolError::BufferTooSmall)?;
    let (kind, signal, value) = match notification {
        Notification::None => (0u32, 0u32, 0u64),
        Notification::Default => (1, 0, 0),
        Notification::Signal { signal, value } if (1..=crate::SIGNAL_MAX).contains(&signal) => {
            (2, signal, value)
        }
        Notification::Thread { cookie } if cookie != 0 => (3, 0, cookie),
        _ => return Err(invalid()),
    };
    out.fill(0);
    out[..2].copy_from_slice(&1u16.to_le_bytes());
    out[4..8].copy_from_slice(&(clock as u32).to_le_bytes());
    out[8..12].copy_from_slice(&kind.to_le_bytes());
    out[12..16].copy_from_slice(&signal.to_le_bytes());
    out[16..24].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

pub fn decode_create(input: &[u8]) -> Result<(Clock, Notification), ProtocolError> {
    if input.len() != CREATE_LEN || input[..4] != [1, 0, 0, 0] {
        return Err(invalid());
    }
    let clock = match u32::from_le_bytes(input[4..8].try_into().unwrap()) {
        1 => Clock::Realtime,
        2 => Clock::Monotonic,
        3 => Clock::ProcessCpu,
        4 => Clock::ThreadCpu,
        _ => return Err(invalid()),
    };
    let kind = u32::from_le_bytes(input[8..12].try_into().unwrap());
    let signal = u32::from_le_bytes(input[12..16].try_into().unwrap());
    let value = u64::from_le_bytes(input[16..24].try_into().unwrap());
    let notification = match (kind, signal, value) {
        (0, 0, 0) => Notification::None,
        (1, 0, 0) => Notification::Default,
        (2, signal, value) if (1..=crate::SIGNAL_MAX).contains(&signal) => {
            Notification::Signal { signal, value }
        }
        (3, 0, cookie) if cookie != 0 => Notification::Thread { cookie },
        _ => return Err(invalid()),
    };
    Ok((clock, notification))
}

pub fn decode_id(input: &[u8]) -> Result<u64, ProtocolError> {
    let id = u64::from_le_bytes(input.try_into().map_err(|_| invalid())?);
    if id == 0 { Err(invalid()) } else { Ok(id) }
}

pub fn encode_value(value: Value, out: &mut [u8]) -> Result<(), ProtocolError> {
    if value.remaining_ns > MAX_DURATION_NS || value.interval_ns > MAX_DURATION_NS {
        return Err(invalid());
    }
    let out = out
        .get_mut(..VALUE_LEN)
        .ok_or(ProtocolError::BufferTooSmall)?;
    out[..16].copy_from_slice(&value.remaining_ns.to_le_bytes());
    out[16..].copy_from_slice(&value.interval_ns.to_le_bytes());
    Ok(())
}

pub fn decode_value(input: &[u8]) -> Result<Value, ProtocolError> {
    if input.len() != VALUE_LEN {
        return Err(invalid());
    }
    let value = Value {
        remaining_ns: u128::from_le_bytes(input[..16].try_into().unwrap()),
        interval_ns: u128::from_le_bytes(input[16..].try_into().unwrap()),
    };
    encode_value(value, &mut [0; VALUE_LEN])?;
    Ok(value)
}

pub fn encode_set(
    id: u64,
    absolute: bool,
    value: Value,
    out: &mut [u8],
) -> Result<(), ProtocolError> {
    if id == 0 {
        return Err(invalid());
    }
    let out = out
        .get_mut(..SET_LEN)
        .ok_or(ProtocolError::BufferTooSmall)?;
    encode_value(value, &mut out[16..])?;
    out[..8].copy_from_slice(&id.to_le_bytes());
    out[8..12].copy_from_slice(&u32::from(absolute).to_le_bytes());
    out[12..16].fill(0);
    Ok(())
}

pub fn decode_set(input: &[u8]) -> Result<(u64, bool, Value), ProtocolError> {
    if input.len() != SET_LEN || input[12..16] != [0; 4] {
        return Err(invalid());
    }
    let id = decode_id(&input[..8])?;
    let absolute = match u32::from_le_bytes(input[8..12].try_into().unwrap()) {
        0 => false,
        1 => true,
        _ => return Err(invalid()),
    };
    Ok((id, absolute, decode_value(&input[16..])?))
}
