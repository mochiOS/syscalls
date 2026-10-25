//! Validate all fields before publishing the mochiOS rusage C representation.
use super::*;
use mochios_posix_client::accounting::cpu_timeval;

pub(super) const LEN: usize = 40;

pub(super) fn encode(usage: posix_protocol::wait_usage::Usage) -> Result<[u8; LEN], c_int> {
    let cpu = usage.cpu;
    if cpu.ticks_per_second == 0 && usage.peak_resident_bytes != 0 {
        return Err(EIO);
    }
    let (user_seconds, user_microseconds) = cpu_timeval(cpu.user_ticks, cpu.ticks_per_second)?;
    let (kernel_seconds, kernel_microseconds) =
        cpu_timeval(cpu.kernel_ticks, cpu.ticks_per_second)?;
    let kib = usage.peak_resident_bytes / 1024 + u64::from(usage.peak_resident_bytes % 1024 != 0);
    let peak = i64::try_from(kib).map_err(|_| EOVERFLOW)?;
    let mut bytes = [0; LEN];
    for (slot, value) in bytes.chunks_exact_mut(8).zip([
        user_seconds,
        user_microseconds,
        kernel_seconds,
        kernel_microseconds,
        peak,
    ]) {
        slot.copy_from_slice(&value.to_ne_bytes());
    }
    Ok(bytes)
}
