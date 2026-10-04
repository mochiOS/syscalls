pub const GRND_NONBLOCK: u32 = 1 << 0;
pub const GRND_RANDOM: u32 = 1 << 1;
pub const GETRANDOM_FLAGS_ALL: u32 = GRND_NONBLOCK | GRND_RANDOM;

/// Validates POSIX/Linux-compatible getrandom flags before the request reaches
/// the native mnu random source. mnu exposes no POSIX flag ABI.
pub const fn flags_are_supported(flags: u32) -> bool {
    flags & !GETRANDOM_FLAGS_ALL == 0
}
