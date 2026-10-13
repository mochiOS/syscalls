/// Clock classes for the newlib SDK's `clockid_t` ABI. These selectors are not
/// Linux clock IDs; native mnu selectors are chosen by the runtime afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockKind {
    Realtime,
    Monotonic,
    ProcessCpu,
    ThreadCpu,
}

pub const fn classify_clock_id(clock_id: i32) -> Option<ClockKind> {
    match clock_id {
        0 | 1 | 8 => Some(ClockKind::Realtime),
        4 | 5 | 6 | 7 | 9 => Some(ClockKind::Monotonic),
        2 => Some(ClockKind::ProcessCpu),
        3 => Some(ClockKind::ThreadCpu),
        _ => None,
    }
}

/// Convert a native source quantum into a normalized POSIX timespec.
/// Zero is malformed metadata, not a claim of infinitely precise time.
pub fn clock_resolution(quantum_nanoseconds: u64) -> Result<(i64, i64), i32> {
    if quantum_nanoseconds == 0 {
        return Err(crate::newlib_errno::EIO);
    }
    Ok((
        (quantum_nanoseconds / 1_000_000_000) as i64,
        (quantum_nanoseconds % 1_000_000_000) as i64,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SleepObservation {
    Waiting,
    Complete,
    Interrupted { remaining_nanoseconds: u64 },
}

/// A caught handler interrupts POSIX nanosleep regardless of restart policy.
/// Ignored/blocked signals do not increment the thread's handler generation.
pub const fn observe_sleep(deadline: u64, now: u64, before: u64, after: u64) -> SleepObservation {
    if before != after {
        SleepObservation::Interrupted {
            remaining_nanoseconds: deadline.saturating_sub(now),
        }
    } else if now >= deadline {
        SleepObservation::Complete
    } else {
        SleepObservation::Waiting
    }
}

/// The historic newlib TIMER_ABSTIME value, not the Linux flag value.
pub const TIMER_ABSTIME: i32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockSleep {
    pub clock: ClockKind,
    pub absolute: bool,
    pub nanoseconds: u64,
}

impl ClockSleep {
    pub fn parse(clock_id: i32, flags: i32, seconds: i64, nanoseconds: i64) -> Result<Self, i32> {
        use crate::newlib_errno::{EINVAL, ENOTSUP};
        if flags & !TIMER_ABSTIME != 0 || seconds < 0 || !(0..1_000_000_000).contains(&nanoseconds)
        {
            return Err(EINVAL);
        }
        let clock = match clock_id {
            1 => ClockKind::Realtime,
            4 => ClockKind::Monotonic,
            3 => return Err(EINVAL), // A thread cannot sleep against its own CPU clock.
            other if classify_clock_id(other).is_some() => return Err(ENOTSUP),
            _ => return Err(EINVAL),
        };
        let nanoseconds = (seconds as u64)
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(nanoseconds as u64))
            .ok_or(EINVAL)?;
        Ok(Self {
            clock,
            absolute: flags == TIMER_ABSTIME,
            nanoseconds,
        })
    }

    pub fn remaining(self, selected_now: u64) -> u64 {
        self.nanoseconds.saturating_sub(selected_now)
    }
}
