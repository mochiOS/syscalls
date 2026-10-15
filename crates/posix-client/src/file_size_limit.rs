//! POSIX file-size policy, independent of native Handle/VM mechanisms.
use mochios_posix_protocol::RLIM_INFINITY;

/// Length of a permitted positioned write. None means no nonempty prefix
/// fits: the caller must generate SIGXFSZ and report EFBIG. A crossing write
/// succeeds with the permitted prefix, without generating a signal.
///
/// Validate descriptor type/access, signed offsets and ssize_t bounds first.
/// This calculation needs no shared cursor or file-size query. It must not
/// be used with a separately queried sequential/append cursor (TOCTOU).
/// Zero-byte operations never fail merely because of this resource limit.
/// https://pubs.opengroup.org/onlinepubs/9699919799/functions/write.html
pub const fn positioned_length(offset: u64, length: usize, soft: u64) -> Option<usize> {
    if length == 0 || soft == RLIM_INFINITY {
        return Some(length);
    }
    if offset >= soft {
        return None;
    }
    let remaining = soft - offset;
    Some(if remaining < length as u64 {
        remaining as usize
    } else {
        length
    })
}
