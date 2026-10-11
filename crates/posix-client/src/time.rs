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
