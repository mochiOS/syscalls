use super::{ProtocolError, get_u32, get_u64, put_u32, put_u64};

/// Explicit signed Unix time, provider-selected current time, or no change.
/// No host timespec layout or special tv_nsec constants appear on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampUpdate {
    Set { seconds: i64, nanoseconds: u32 },
    Now,
    Omit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileTimeUpdate {
    pub access: TimestampUpdate,
    pub modification: TimestampUpdate,
}

impl FileTimeUpdate {
    pub const fn unchanged(self) -> bool {
        matches!(self.access, TimestampUpdate::Omit)
            && matches!(self.modification, TimestampUpdate::Omit)
    }

    pub const fn both_now(self) -> bool {
        matches!(self.access, TimestampUpdate::Now)
            && matches!(self.modification, TimestampUpdate::Now)
    }

    pub const fn valid(self) -> bool {
        const fn valid_one(value: TimestampUpdate) -> bool {
            match value {
                TimestampUpdate::Set { nanoseconds, .. } => nanoseconds < 1_000_000_000,
                _ => true,
            }
        }
        valid_one(self.access) && valid_one(self.modification)
    }
}

/// Two 16-byte records: u32 tag, i64 seconds, u32 nanoseconds (little endian).
/// Tags: 0 explicit, 1 current, 2 unchanged. Non-explicit records have zero data.
pub const TIME_UPDATE_LEN: usize = 32;

pub fn encode_time_update(
    value: FileTimeUpdate,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    if !value.valid() {
        return Err(ProtocolError::InvalidLength);
    }
    let output = output
        .get_mut(..TIME_UPDATE_LEN)
        .ok_or(ProtocolError::BufferTooSmall)?;
    for (field, output) in [value.access, value.modification]
        .into_iter()
        .zip(output.chunks_exact_mut(16))
    {
        let (tag, seconds, nanoseconds) = match field {
            TimestampUpdate::Set {
                seconds,
                nanoseconds,
            } => (0, seconds, nanoseconds),
            TimestampUpdate::Now => (1, 0, 0),
            TimestampUpdate::Omit => (2, 0, 0),
        };
        put_u32(output, 0, tag);
        put_u64(output, 4, seconds as u64);
        put_u32(output, 12, nanoseconds);
    }
    Ok(TIME_UPDATE_LEN)
}

/// Decode the fixed prefix, returning an unmodified trailing path payload.
pub fn decode_time_update(input: &[u8]) -> Result<(FileTimeUpdate, &[u8]), ProtocolError> {
    let (fields, remaining) = input
        .split_at_checked(TIME_UPDATE_LEN)
        .ok_or(ProtocolError::InvalidLength)?;
    fn decode_one(field: &[u8]) -> Result<TimestampUpdate, ProtocolError> {
        let seconds = get_u64(field, 4) as i64;
        let nanoseconds = get_u32(field, 12);
        match get_u32(field, 0) {
            0 if nanoseconds < 1_000_000_000 => Ok(TimestampUpdate::Set {
                seconds,
                nanoseconds,
            }),
            1 if seconds == 0 && nanoseconds == 0 => Ok(TimestampUpdate::Now),
            2 if seconds == 0 && nanoseconds == 0 => Ok(TimestampUpdate::Omit),
            _ => Err(ProtocolError::InvalidLength),
        }
    }
    Ok((
        FileTimeUpdate {
            access: decode_one(&fields[..16])?,
            modification: decode_one(&fields[16..])?,
        },
        remaining,
    ))
}
