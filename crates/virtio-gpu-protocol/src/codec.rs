use crate::{DecodeError, EncodeError};

pub(crate) fn require_encode(buffer: &[u8], required: usize) -> Result<(), EncodeError> {
    if buffer.len() < required {
        return Err(EncodeError::BufferTooSmall {
            required,
            actual: buffer.len(),
        });
    }
    Ok(())
}

pub(crate) fn require_decode(buffer: &[u8], expected: usize) -> Result<(), DecodeError> {
    if buffer.len() != expected {
        return Err(DecodeError::InvalidLength {
            expected,
            actual: buffer.len(),
        });
    }
    Ok(())
}

pub(crate) fn read_u8(buffer: &[u8], offset: usize) -> Result<u8, DecodeError> {
    buffer
        .get(offset)
        .copied()
        .ok_or(DecodeError::InvalidLength {
            expected: offset.saturating_add(1),
            actual: buffer.len(),
        })
}

pub(crate) fn read_u32(buffer: &[u8], offset: usize) -> Result<u32, DecodeError> {
    let bytes = buffer
        .get(offset..offset.saturating_add(4))
        .ok_or(DecodeError::InvalidLength {
            expected: offset.saturating_add(4),
            actual: buffer.len(),
        })?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(crate) fn read_u64(buffer: &[u8], offset: usize) -> Result<u64, DecodeError> {
    let bytes = buffer
        .get(offset..offset.saturating_add(8))
        .ok_or(DecodeError::InvalidLength {
            expected: offset.saturating_add(8),
            actual: buffer.len(),
        })?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

pub(crate) fn write_u8(buffer: &mut [u8], offset: usize, value: u8) {
    buffer[offset] = value;
}

pub(crate) fn write_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn write_u64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
