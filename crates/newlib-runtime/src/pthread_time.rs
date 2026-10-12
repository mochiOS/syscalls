//! Absolute pthread timeouts translated to native monotonic wait deadlines.

use super::*;

pub(super) fn deadline(clock: c_int, absolute: u64) -> Result<u64, c_int> {
    let now = monotonic_nanoseconds()?;
    let selected_now = if clock == 4 {
        now
    } else {
        let mut instant = mnu_abi::ClockInstant::default();
        syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::ClockRead,
            mnu_abi::ClockId::Realtime as u64,
            (&mut instant as *mut mnu_abi::ClockInstant) as u64,
        ))?;
        if instant.nanoseconds >= 1_000_000_000 || instant.reserved != 0 {
            return Err(EIO);
        }
        instant
            .seconds
            .checked_mul(1_000_000_000)
            .and_then(|n| n.checked_add(u64::from(instant.nanoseconds)))
            .ok_or(EOVERFLOW)?
    };
    now.checked_add(absolute.saturating_sub(selected_now))
        // A finite pthread timeout must not become the native infinite sentinel.
        .filter(|value| *value != syscall::ADDRESS_WAIT_INFINITE)
        .ok_or(EOVERFLOW)
}
