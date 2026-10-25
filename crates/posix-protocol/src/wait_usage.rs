//! One selected child event and accounting snapshot from a single transaction.
use crate::{ProtocolError, WaitInfo, WaitedChildCpuUsage};

pub const USAGE_LEN: usize = crate::WAITED_CHILD_CPU_USAGE_LEN + 8;
pub const LEN: usize = crate::WAIT_INFO_LEN + USAGE_LEN;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub cpu: WaitedChildCpuUsage,
    pub peak_resident_bytes: u64,
}

pub fn encode_usage(value: Usage, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < USAGE_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if value.cpu.ticks_per_second == 0 && value.peak_resident_bytes != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    crate::encode_waited_child_cpu_usage(value.cpu, output)?;
    output[crate::WAITED_CHILD_CPU_USAGE_LEN..USAGE_LEN]
        .copy_from_slice(&value.peak_resident_bytes.to_le_bytes());
    Ok(())
}

pub fn decode_usage(input: &[u8]) -> Result<Usage, ProtocolError> {
    if input.len() != USAGE_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let value = Usage {
        cpu: crate::decode_waited_child_cpu_usage(&input[..crate::WAITED_CHILD_CPU_USAGE_LEN])?,
        peak_resident_bytes: u64::from_le_bytes(
            input[crate::WAITED_CHILD_CPU_USAGE_LEN..]
                .try_into()
                .unwrap(),
        ),
    };
    if value.cpu.ticks_per_second == 0 && value.peak_resident_bytes != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Observation {
    pub info: WaitInfo,
    pub usage: Usage,
}

fn validate(value: Observation) -> Result<(), ProtocolError> {
    if value.info.result.process_id == 0 {
        if value != Observation::default() {
            return Err(ProtocolError::InvalidLength);
        }
    } else if value.usage.cpu.ticks_per_second == 0 {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(())
}

pub fn encode(value: Observation, output: &mut [u8]) -> Result<(), ProtocolError> {
    validate(value)?;
    if output.len() < LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    crate::encode_wait_info(value.info, &mut output[..crate::WAIT_INFO_LEN])?;
    encode_usage(value.usage, &mut output[crate::WAIT_INFO_LEN..LEN])
}

pub fn decode(input: &[u8]) -> Result<Observation, ProtocolError> {
    if input.len() != LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let value = Observation {
        info: crate::decode_wait_info(&input[..crate::WAIT_INFO_LEN])?,
        usage: decode_usage(&input[crate::WAIT_INFO_LEN..])?,
    };
    validate(value)?;
    Ok(value)
}
