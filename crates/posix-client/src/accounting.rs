use crate::newlib_errno::{EIO, EOVERFLOW};

/// Matches the newlib SDK's CLOCKS_PER_SEC and sysconf(_SC_CLK_TCK).
pub const CLOCK_TICKS_PER_SECOND: u64 = 1000;

/// Convert after aggregation. Quotient/remainder avoids overflowing a large
/// intermediate product when the final clock_t remains representable.
pub fn clock_ticks(ticks: u128, sampling_rate: u64) -> Result<u64, i32> {
    if sampling_rate == 0 {
        return if ticks == 0 { Ok(0) } else { Err(EIO) };
    }
    let rate = u128::from(sampling_rate);
    let scale = u128::from(CLOCK_TICKS_PER_SECOND);
    let whole = (ticks / rate).checked_mul(scale).ok_or(EOVERFLOW)?;
    let fractional = (ticks % rate) * scale / rate;
    let value = whole.checked_add(fractional).ok_or(EOVERFLOW)?;
    // The SDK uses unsigned long; (clock_t)-1 is the failure sentinel.
    let value = u64::try_from(value).map_err(|_| EOVERFLOW)?;
    if value == u64::MAX {
        Err(EOVERFLOW)
    } else {
        Ok(value)
    }
}

pub fn elapsed_clock_ticks(seconds: u64, nanoseconds: u32) -> Result<u64, i32> {
    if nanoseconds >= 1_000_000_000 {
        return Err(EIO);
    }
    clock_ticks(
        u128::from(seconds) * 1_000_000_000 + u128::from(nanoseconds),
        1_000_000_000,
    )
}
