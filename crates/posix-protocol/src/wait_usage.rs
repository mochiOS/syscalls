//! One selected child event and accounting snapshot from a single transaction.
use crate::{ProtocolError, WaitInfo, WaitedChildCpuUsage};

pub const LEN: usize = crate::WAIT_INFO_LEN + crate::WAITED_CHILD_CPU_USAGE_LEN;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Observation {
    pub info: WaitInfo,
    pub usage: WaitedChildCpuUsage,
}

fn validate(value: Observation) -> Result<(), ProtocolError> {
    if value.info.result.process_id == 0 {
        if value != Observation::default() {
            return Err(ProtocolError::InvalidLength);
        }
    } else if value.usage.ticks_per_second == 0 {
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
    crate::encode_waited_child_cpu_usage(value.usage, &mut output[crate::WAIT_INFO_LEN..LEN])
}

pub fn decode(input: &[u8]) -> Result<Observation, ProtocolError> {
    if input.len() != LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let value = Observation {
        info: crate::decode_wait_info(&input[..crate::WAIT_INFO_LEN])?,
        usage: crate::decode_waited_child_cpu_usage(&input[crate::WAIT_INFO_LEN..])?,
    };
    validate(value)?;
    Ok(value)
}
