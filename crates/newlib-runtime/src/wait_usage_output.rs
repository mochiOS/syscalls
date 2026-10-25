//! Publish the selected event only after validating all CPU conversions.
use super::*;

pub(super) fn publish(
    observation: posix_protocol::wait_usage::Observation,
    status: *mut c_int,
    usage: *mut c_void,
) -> Result<c_int, c_int> {
    if observation.info.result.process_id == 0 {
        return Ok(0);
    }
    let pid = c_int::try_from(observation.info.result.process_id).map_err(|_| EOVERFLOW)?;
    let bytes = resource_usage_output::encode(observation.usage)?;
    wait_output::publish(
        observation.info.result.process_id,
        observation.info.result.status,
        status,
    )?;
    user_copy::write(usage.cast(), &bytes)?;
    Ok(pid)
}
