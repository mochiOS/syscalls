//! Publish the selected event only after validating all CPU conversions.
use super::*;
use mochios_posix_client::accounting::cpu_timeval;

pub(super) fn publish(
    observation: posix_protocol::wait_usage::Observation,
    status: *mut c_int,
    usage: *mut c_void,
) -> Result<c_int, c_int> {
    if observation.info.result.process_id == 0 {
        return Ok(0);
    }
    let pid = c_int::try_from(observation.info.result.process_id).map_err(|_| EOVERFLOW)?;
    let cpu = observation.usage;
    let (user_seconds, user_microseconds) = cpu_timeval(cpu.user_ticks, cpu.ticks_per_second)?;
    let (kernel_seconds, kernel_microseconds) =
        cpu_timeval(cpu.kernel_ticks, cpu.ticks_per_second)?;
    // mochiOS newlib's rusage contains exactly two timeval fields (32 bytes).
    // No unmeasured RSS/fault counters are fabricated or written past its ABI.
    let mut bytes = [0; 32];
    for (slot, value) in bytes.chunks_exact_mut(8).zip([
        user_seconds,
        user_microseconds,
        kernel_seconds,
        kernel_microseconds,
    ]) {
        slot.copy_from_slice(&value.to_ne_bytes());
    }
    wait_output::publish(
        observation.info.result.process_id,
        observation.info.result.status,
        status,
    )?;
    user_copy::write(usage.cast(), &bytes)?;
    Ok(pid)
}
