pub const GRND_NONBLOCK: u32 = 1 << 0;
pub const GRND_RANDOM: u32 = 1 << 1;
pub const GETRANDOM_FLAGS_ALL: u32 = GRND_NONBLOCK | GRND_RANDOM;

/// Validates POSIX/Linux-compatible getrandom flags before the request reaches
/// the native mnu random source. mnu exposes no POSIX flag ABI.
pub const fn flags_are_supported(flags: u32) -> bool {
    flags & !GETRANDOM_FLAGS_ALL == 0
}

/// Complete the small, all-or-error UNIX getentropy request using the native
/// random source. Interrupted and short transfers do not imply completion.
/// The callback receives only the unfilled range, never a caller pointer.
pub fn fill_entropy(
    length: usize,
    mut fill: impl FnMut(usize, usize) -> Result<usize, i32>,
) -> Result<(), i32> {
    use crate::newlib_errno::{EINTR, EIO};
    if length > 256 {
        return Err(EIO);
    }
    let mut offset = 0;
    while offset < length {
        let remaining = length - offset;
        match fill(offset, remaining) {
            Ok(count) if count != 0 && count <= remaining => offset += count,
            Ok(_) => return Err(EIO),
            Err(EINTR) => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
