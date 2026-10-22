//! Per-read noncanonical batching/timers. Terminal settings remain user-space
//! policy; the backend supplies ordinary reads and cancellable native waits.
use crate::protocol::TerminalReadSettings;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attempt {
    Bytes(usize),
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error<E> {
    Io(E),
    InvalidResult,
}

fn failed<E>(total: usize, error: E) -> Result<usize, Error<E>> {
    if total == 0 {
        Err(Error::Io(error))
    } else {
        Ok(total)
    }
}

/// Each positive backend result has already copied that prefix to the caller.
/// `read` receives its output offset and remaining capacity. `wait` returns
/// false only on a real deadline expiry; None denotes an unbounded wait.
/// Nonblocking mode performs exactly one attempt and reports unavailability
/// through `unavailable`, irrespective of MIN/TIME (permitted by POSIX).
pub fn read<E>(
    settings: TerminalReadSettings,
    capacity: usize,
    nonblocking: bool,
    unavailable: E,
    mut read: impl FnMut(usize, usize) -> Result<Attempt, E>,
    mut clock: impl FnMut() -> Result<u64, E>,
    mut wait: impl FnMut(Option<u64>) -> Result<bool, E>,
) -> Result<usize, Error<E>> {
    if capacity == 0 {
        return Ok(0);
    }
    let minimum = usize::from(settings.minimum).min(capacity);
    let interval = u64::from(settings.deciseconds) * 100_000_000;
    let deadline_after = |now: u64| now.saturating_add(interval).min(u64::MAX - 1);
    let mut deadline = if !nonblocking && settings.noncanonical && minimum == 0 && interval != 0 {
        Some(deadline_after(clock().map_err(Error::Io)?))
    } else {
        None
    };
    let mut total = 0;
    loop {
        match read(total, capacity - total) {
            Ok(Attempt::Bytes(count)) => {
                if count > capacity - total {
                    return Err(Error::InvalidResult);
                }
                total += count;
                if count == 0
                    || nonblocking
                    || !settings.noncanonical
                    || minimum == 0
                    || total >= minimum
                {
                    return Ok(total);
                }
                // With MIN>0, TIME is inter-byte: no timer before the first
                // byte, and every received batch restarts it. No persistent
                // OFD timer is shared by concurrent reads or inherited FDs.
                if interval != 0 {
                    deadline = match clock() {
                        Ok(now) => Some(deadline_after(now)),
                        Err(error) => return failed(total, error),
                    };
                }
            }
            Ok(Attempt::Unavailable) => {
                if nonblocking {
                    return failed(total, unavailable);
                }
                if settings.noncanonical && minimum == 0 && interval == 0 {
                    return Ok(total);
                }
                if let Some(end) = deadline {
                    match clock() {
                        Ok(now) if now >= end => return Ok(total),
                        Ok(_) => {}
                        Err(error) => return failed(total, error),
                    }
                }
                match wait(deadline) {
                    Ok(true) => {}
                    Ok(false) if deadline.is_some() => return Ok(total),
                    Ok(false) => return Err(Error::InvalidResult),
                    Err(error) => return failed(total, error),
                }
            }
            Err(error) => return failed(total, error),
        }
    }
}
