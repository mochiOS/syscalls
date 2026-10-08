use mochios_posix_protocol::{SIGNAL_KILL, SIGNAL_MAX, SIGNAL_STOP};

pub const SIGNAL_SET_MASK: i32 = 0;
pub const SIGNAL_BLOCK: i32 = 1;
pub const SIGNAL_UNBLOCK: i32 = 2;

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
