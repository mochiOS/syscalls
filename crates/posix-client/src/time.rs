/// POSIX clock classes after translating platform-specific `clockid_t`
/// aliases. Native mnu clock selectors are chosen by the runtime afterwards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockKind {
    Realtime,
    Monotonic,
    ProcessCpu,
    ThreadCpu,
}

pub const fn classify_clock_id(clock_id: i32) -> Option<ClockKind> {
    match clock_id {
        0 | 5 | 8 => Some(ClockKind::Realtime),
        1 | 4 | 6 | 7 | 9 => Some(ClockKind::Monotonic),
        2 => Some(ClockKind::ProcessCpu),
        3 => Some(ClockKind::ThreadCpu),
        _ => None,
    }
}
