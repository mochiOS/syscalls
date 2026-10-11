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

pub fn timespec_timeout_nanoseconds(seconds: i64, nanoseconds: i64) -> Option<u64> {
    if seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds) {
        return None;
    }
    (seconds as u64)
        .checked_mul(1_000_000_000)?
        .checked_add(nanoseconds as u64)
}

/// Install the temporary pselect/ppoll mask and restore it on every returning
/// path, including operation errors. The caller captures its handler generation
/// before replacement and uses that generation in its guarded native wait.
pub fn with_signal_mask<T, E>(
    mask: Option<u64>,
    mut replace: impl FnMut(u64) -> Result<u64, E>,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let previous = mask.map(&mut replace).transpose()?;
    let result = operation();
    if let Some(previous) = previous {
        replace(previous)?;
    }
    result
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
