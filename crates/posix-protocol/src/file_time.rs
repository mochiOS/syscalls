//! POSIX time-change requests, independent of the filesystem provider protocol.
//! C pointers, ABI padding and platform-specific UTIME constants never cross IPC.
use crate::{ProtocolError, STAT_AT_HEADER_LEN, StatAtRequest, decode_stat_at, encode_stat_at};

pub const UPDATE_LEN: usize = 32;
pub const AT_HEADER_LEN: usize = UPDATE_LEN + STAT_AT_HEADER_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Set { seconds: i64, nanoseconds: u32 },
    Now,
    Omit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Update {
    pub access: Change,
    pub modification: Change,
}

impl Update {
    pub const fn now() -> Self {
        Self {
            access: Change::Now,
            modification: Change::Now,
        }
    }

    pub const fn valid(self) -> bool {
        const fn valid(value: Change) -> bool {
            match value {
                Change::Set { nanoseconds, .. } => nanoseconds < 1_000_000_000,
                _ => true,
            }
        }
        valid(self.access) && valid(self.modification)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AtRequest<'a> {
    pub target: StatAtRequest<'a>,
    pub times: Update,
}

/// Two 16-byte records: little-endian u32 tag, i64 seconds, u32 nanoseconds.
/// Tags 0/1/2 mean explicit/current/unchanged. Non-explicit data must be zero.
pub fn encode(value: Update, output: &mut [u8]) -> Result<usize, ProtocolError> {
    if !value.valid() {
        return Err(ProtocolError::InvalidLength);
    }
    let output = output
        .get_mut(..UPDATE_LEN)
        .ok_or(ProtocolError::BufferTooSmall)?;
    for (field, output) in [value.access, value.modification]
        .into_iter()
        .zip(output.chunks_exact_mut(16))
    {
        let (tag, seconds, nanoseconds) = match field {
            Change::Set {
                seconds,
                nanoseconds,
            } => (0u32, seconds, nanoseconds),
            Change::Now => (1, 0, 0),
            Change::Omit => (2, 0, 0),
        };
        output[..4].copy_from_slice(&tag.to_le_bytes());
        output[4..12].copy_from_slice(&seconds.to_le_bytes());
        output[12..].copy_from_slice(&nanoseconds.to_le_bytes());
    }
    Ok(UPDATE_LEN)
}

pub fn decode(input: &[u8]) -> Result<Update, ProtocolError> {
    if input.len() != UPDATE_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    fn field(input: &[u8]) -> Result<Change, ProtocolError> {
        let tag = u32::from_le_bytes(input[..4].try_into().unwrap());
        let seconds = i64::from_le_bytes(input[4..12].try_into().unwrap());
        let nanoseconds = u32::from_le_bytes(input[12..].try_into().unwrap());
        match tag {
            0 if nanoseconds < 1_000_000_000 => Ok(Change::Set {
                seconds,
                nanoseconds,
            }),
            1 if seconds == 0 && nanoseconds == 0 => Ok(Change::Now),
            2 if seconds == 0 && nanoseconds == 0 => Ok(Change::Omit),
            _ => Err(ProtocolError::InvalidLength),
        }
    }
    Ok(Update {
        access: field(&input[..16])?,
        modification: field(&input[16..])?,
    })
}

pub fn encode_at(request: AtRequest<'_>, output: &mut [u8]) -> Result<usize, ProtocolError> {
    if !request.times.valid() {
        return Err(ProtocolError::InvalidLength);
    }
    if output.len() < AT_HEADER_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    let path_len = encode_stat_at(request.target, &mut output[UPDATE_LEN..])?;
    encode(request.times, output)?;
    Ok(UPDATE_LEN + path_len)
}

pub fn decode_at(input: &[u8]) -> Result<AtRequest<'_>, ProtocolError> {
    let (times, target) = input
        .split_at_checked(UPDATE_LEN)
        .ok_or(ProtocolError::InvalidLength)?;
    Ok(AtRequest {
        times: decode(times)?,
        target: decode_stat_at(target)?,
    })
}
