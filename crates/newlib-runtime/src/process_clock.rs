//! Own-process samples stay native; foreign process clocks need the service's
//! registered-object lifetime and POSIX credential checks on each observation.
//! IDs identify a process, so a copied ID still names the parent after fork.
use super::*;
use mochios_posix_client::process_clock::{clock_id, target, timespec};
use posix_protocol::process_clock::Sample;

fn sample(pid: u64) -> Result<Sample, c_int> {
    if pid == native_process_id().map_err(|error| map_kernel_errno(error.raw()))? {
        let usage =
            syscall::execution::usage(None).map_err(|error| map_kernel_errno(error.raw()))?;
        return Ok(Sample {
            process_id: pid,
            user_ticks: usage.user_ticks,
            kernel_ticks: usage.kernel_ticks,
            ticks_per_second: usage.ticks_per_second,
        });
    }
    posix_client()
        .map_err(map_posix_client_error)?
        .process_cpu_clock(pid)
        .map_err(map_posix_client_error)
}

pub(super) fn nanoseconds(pid: u64) -> Result<u128, c_int> {
    let (seconds, nanoseconds) = timespec(sample(pid)?)?;
    Ok(seconds as u128 * 1_000_000_000 + nanoseconds as u128)
}

#[unsafe(no_mangle)]
pub extern "C" fn clock_getcpuclockid(pid: c_int, output: *mut u64) -> c_int {
    let saved_errno = unsafe { *__errno() };
    let result = (|| {
        if output.is_null() {
            return Err(EFAULT);
        }
        if pid < 0 {
            return Err(ESRCH);
        }
        let pid = if pid == 0 {
            native_process_id().map_err(|error| map_kernel_errno(error.raw()))?
        } else {
            pid as u64
        };
        let id = clock_id(pid).ok_or(EOVERFLOW)?;
        sample(pid)?;
        user_copy::write(output.cast(), &id.to_ne_bytes())
    })();
    set_errno(saved_errno);
    result.err().unwrap_or(0)
}

fn reading(id: u64) -> Result<Sample, c_int> {
    sample(target(id).ok_or(EINVAL)?).map_err(|error| if error == ESRCH { EINVAL } else { error })
}

pub(super) fn read(id: u64, output: *mut Timespec) -> Result<c_int, c_int> {
    let (tv_sec, tv_nsec) = timespec(reading(id)?)?;
    time_memory::write_timespec(output, Timespec { tv_sec, tv_nsec })?;
    Ok(0)
}

pub(super) fn resolution(id: u64, output: *mut Timespec) -> Result<c_int, c_int> {
    let sample = reading(id)?;
    let quantum = (1_000_000_000u128.div_ceil(u128::from(sample.ticks_per_second))).max(1);
    let (tv_sec, tv_nsec) = mochios_posix_client::time::clock_resolution(quantum as u64)?;
    if !output.is_null() {
        time_memory::write_timespec(output, Timespec { tv_sec, tv_nsec })?;
    }
    Ok(0)
}
