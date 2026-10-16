//! Path metadata uses the shared snapshot/authority scope during RPC.
use super::*;

pub(super) fn at(dirfd: c_int, path: *const c_char, flags: u64) -> Result<NewlibStat, c_int> {
    let flags = match flags {
        0 => 0,
        AT_SYMLINK_NOFOLLOW => STAT_NOFOLLOW,
        _ => return Err(EINVAL),
    };
    let result = path_io::at(dirfd, path, |base, path| {
        let client = posix_client().map_err(map_posix_client_error)?;
        let status = client
            .stat_at(base, flags, path)
            .map_err(map_posix_client_error)?;
        translate_posix_stat(&status)
    });
    // Only the copied stat value remains when pending C handlers run.
    drain_pending_signals()?;
    result
}
