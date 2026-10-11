/// Counts selected bits across all three POSIX `select` result sets.
/// A descriptor selected in multiple sets contributes once per set, not once
/// per descriptor. The caller has already excluded bits above `nfds`.
pub const fn select_ready_count(read: u64, write: u64, exceptional: u64) -> u32 {
    read.count_ones() + write.count_ones() + exceptional.count_ones()
}
