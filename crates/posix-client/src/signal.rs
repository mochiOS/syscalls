use mochios_posix_protocol::{SIGNAL_KILL, SIGNAL_MAX, SIGNAL_STOP};

pub const SIGNAL_SET_MASK: i32 = 0;
pub const SIGNAL_BLOCK: i32 = 1;
pub const SIGNAL_UNBLOCK: i32 = 2;
// NSIG in the current newlib target ABI includes signal zero.
pub const NEWLIB_SIGNAL_COUNT: i32 = 32;

pub const fn newlib_set_bit(signal: i32) -> Option<u64> {
    if signal <= 0 || signal >= NEWLIB_SIGNAL_COUNT {
        None
    } else {
        signal_bit(signal as u32)
    }
}

pub const fn signal_bit(signal: u32) -> Option<u64> {
    if signal == 0 || signal > SIGNAL_MAX {
        None
    } else {
        Some(1u64 << (signal - 1))
    }
}

pub const fn unblockable_mask() -> u64 {
    (1u64 << (SIGNAL_KILL - 1)) | (1u64 << (SIGNAL_STOP - 1))
}

pub const fn sanitize_mask(mask: u64) -> u64 {
    mask & !unblockable_mask()
}

pub const fn can_change_disposition(signal: u32) -> bool {
    signal > 0 && signal <= SIGNAL_MAX && signal != SIGNAL_KILL && signal != SIGNAL_STOP
}

pub const fn update_mask(current: u64, operation: i32, requested: u64) -> Option<u64> {
    let requested = sanitize_mask(requested);
    match operation {
        SIGNAL_SET_MASK => Some(requested),
        SIGNAL_BLOCK => Some(current | requested),
        SIGNAL_UNBLOCK => Some(current & !requested),
        _ => None,
    }
}
/// Retries an observed default stop or a known backend job-control interruption
/// whose default signal has been selected for another, not-yet-running thread.
/// Caught handlers, unrelated EINTR, partial transfers and failed signal drains
/// must not turn into an unconditional retry loop. Handler generations are
/// thread-local, but default-stop generations belong to the whole process.
/// `generations` returns (caught-handler count, completed-default-stop count).
/// `default_job_stop` must not classify arbitrary native EINTR as job control.
pub fn terminal_operation<T>(
    mut operation: impl FnMut() -> Result<T, i32>,
    mut drain: impl FnMut() -> Result<(), i32>,
    mut generations: impl FnMut() -> (u64, u64),
    mut default_job_stop: impl FnMut() -> bool,
) -> Result<T, i32> {
    loop {
        let before = generations();
        match operation() {
            Err(crate::newlib_errno::EINTR) => {
                drain()?;
                let after = generations();
                if before.0 != after.0 || (before.1 == after.1 && !default_job_stop()) {
                    return Err(crate::newlib_errno::EINTR);
                }
            }
            result => return result,
        }
    }
}
