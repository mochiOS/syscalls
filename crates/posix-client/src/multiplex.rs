/// Counts selected bits across all three POSIX `select` result sets.
/// A descriptor selected in multiple sets contributes once per set, not once
/// per descriptor. The caller has already excluded bits above `nfds`.
pub const fn select_ready_count(read: u64, write: u64, exceptional: u64) -> u32 {
    read.count_ones() + write.count_ones() + exceptional.count_ones()
}

/// Every negative poll timeout means an infinite wait, not just -1.
/// Nonnegative i32 milliseconds always fit in u64 nanoseconds.
pub const fn poll_timeout_nanoseconds(milliseconds: i32) -> Option<u64> {
    if milliseconds < 0 {
        None
    } else {
        Some(milliseconds as u64 * 1_000_000)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum WaitError<E> {
    Interrupted,
    Io(E),
}

/// poll/select do not restart after a caught handler, including SA_RESTART.
/// A native notification without a caught handler is not a timeout: retry
/// against the original absolute deadline. The backend closes the pre-entry
/// race by guarding its wait with this same captured generation.
pub fn wait<E>(
    captured: u64,
    generation: impl Fn() -> u64,
    mut native_wait: impl FnMut() -> Result<bool, E>,
    mut expired: impl FnMut() -> Result<bool, E>,
) -> Result<(), WaitError<E>> {
    loop {
        if generation() != captured {
            return Err(WaitError::Interrupted);
        }
        let ready = native_wait().map_err(WaitError::Io)?;
        if generation() != captured {
            return Err(WaitError::Interrupted);
        }
        if ready || expired().map_err(WaitError::Io)? {
            return Ok(());
        }
    }
}
