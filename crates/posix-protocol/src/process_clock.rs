//! Explicit wire records for observing an already managed process object.
use crate::ProtocolError;

pub const SAMPLE_LEN: usize = 32;
pub const MAX_PID: u64 = i32::MAX as u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub process_id: u64,
    pub user_ticks: u64,
    pub kernel_ticks: u64,
    pub ticks_per_second: u64,
}

pub fn target(input: &[u8]) -> Result<u64, ProtocolError> {
    let bytes: [u8; 8] = input.try_into().map_err(|_| ProtocolError::InvalidLength)?;
    let pid = u64::from_le_bytes(bytes);
    if pid > MAX_PID {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(pid)
}

pub fn encode(sample: Sample, output: &mut [u8]) -> Result<usize, ProtocolError> {
    if output.len() < SAMPLE_LEN || sample.process_id == 0 || sample.ticks_per_second == 0 {
        return Err(ProtocolError::InvalidLength);
    }
    for (bytes, value) in output[..SAMPLE_LEN].chunks_exact_mut(8).zip([
        sample.process_id,
        sample.user_ticks,
        sample.kernel_ticks,
        sample.ticks_per_second,
    ]) {
        bytes.copy_from_slice(&value.to_le_bytes());
    }
    Ok(SAMPLE_LEN)
}

pub fn decode(input: &[u8]) -> Result<Sample, ProtocolError> {
    if input.len() != SAMPLE_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let value = |offset| u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap());
    let sample = Sample {
        process_id: value(0),
        user_ticks: value(8),
        kernel_ticks: value(16),
        ticks_per_second: value(24),
    };
    if sample.process_id == 0 || sample.ticks_per_second == 0 {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(sample)
}
