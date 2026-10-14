/// Normal byte IO signals do not imply priority or band-specific data.
/// These are libc poll flags, never native kernel interest bits.
pub const NORMAL_READ_EVENTS: i16 = 0x0001 | 0x0040;
pub const NORMAL_WRITE_EVENTS: i16 = 0x0004;

pub const fn immediate_file_events(requested: i16) -> i16 {
    requested & (NORMAL_READ_EVENTS | NORMAL_WRITE_EVENTS)
}

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
    Cancelled,
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
    expired: impl FnMut() -> Result<bool, E>,
) -> Result<(), WaitError<E>> {
    wait_cancellable(
        captured,
        &generation,
        || false,
        &generation,
        |_| native_wait(),
        expired,
    )
}

/// Keeps caught signals and cancellation distinct. The notification snapshot
/// precedes predicate checks and is the backend's native admission guard.
/// Disabled cancellation may wake the wait, but does not interrupt or spin.
/// Cancellation is returned so callers can restore temporary state before
/// running application cleanup; this function never exits a thread.
pub fn wait_cancellable<E>(
    captured: u64,
    generation: impl Fn() -> u64,
    cancellation_requested: impl Fn() -> bool,
    notification_generation: impl Fn() -> u64,
    mut native_wait: impl FnMut(u64) -> Result<bool, E>,
    mut expired: impl FnMut() -> Result<bool, E>,
) -> Result<(), WaitError<E>> {
    loop {
        let notification = notification_generation();
        if cancellation_requested() {
            return Err(WaitError::Cancelled);
        }
        if generation() != captured {
            return Err(WaitError::Interrupted);
        }
        let ready = native_wait(notification).map_err(WaitError::Io)?;
        if cancellation_requested() {
            return Err(WaitError::Cancelled);
        }
        if generation() != captured {
            return Err(WaitError::Interrupted);
        }
        if ready || expired().map_err(WaitError::Io)? {
            return Ok(());
        }
    }
}
