//! Error-number boundary for the mochiOS newlib SDK. Native and service wire
//! statuses are not the C errno ABI; do not expose their numbers unchanged.

pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const ESRCH: i32 = 3;
pub const EINTR: i32 = 4;
pub const EIO: i32 = 5;
pub const E2BIG: i32 = 7;
pub const EBADF: i32 = 9;
pub const ECHILD: i32 = 10;
pub const EAGAIN: i32 = 11;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const EFAULT: i32 = 14;
pub const EBUSY: i32 = 16;
pub const EEXIST: i32 = 17;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const EINVAL: i32 = 22;
pub const EMFILE: i32 = 24;
pub const ENOTTY: i32 = 25;
pub const EFBIG: i32 = 27;
pub const ESPIPE: i32 = 29;
pub const EPIPE: i32 = 32;
pub const ERANGE: i32 = 34;
pub const EDEADLK: i32 = 45;
pub const ENAMETOOLONG: i32 = 91;
pub const ENOSYS: i32 = 88;
pub const ENOTSUP: i32 = 134;
/// Socket-specific unsupported operation; distinct from generic ENOTSUP.
pub const EOPNOTSUPP: i32 = 95;
pub const EOVERFLOW: i32 = 139;

/// Convert a positive newlib C errno to a signed POSIX wire failure.
/// This is not native-status normalization: the numeric namespaces overlap.
/// Invalid/unknown errno values become EIO; success is handled by the caller.
pub const fn to_status(errno: i32) -> i32 {
    let wire = match errno {
        1..=14 | 16..=34 | 60..=63 | 67 | 71 | 96 | 104 | 105 | 111 => errno,
        EDEADLK => 35,
        ENAMETOOLONG => 36,
        46 => 37, // ENOLCK
        ENOSYS => 38,
        90 => 39, // ENOTEMPTY
        92 => 40, // ELOOP
        35 => 42, // ENOMSG
        36 => 43, // EIDRM
        74 => 72, // EMULTIHOP
        77 => 74, // EBADMSG
        EOVERFLOW => 75,
        138 => 84, // EILSEQ
        108 => 88, // ENOTSOCK
        121 => 89, // EDESTADDRREQ
        122 => 90, // EMSGSIZE
        107 => 91, // EPROTOTYPE
        109 => 92, // ENOPROTOOPT
        123 => 93, // EPROTONOSUPPORT
        EOPNOTSUPP | ENOTSUP => 95,
        106 => 97,  // EAFNOSUPPORT
        112 => 98,  // EADDRINUSE
        125 => 99,  // EADDRNOTAVAIL
        115 => 100, // ENETDOWN
        114 => 101, // ENETUNREACH
        126 => 102, // ENETRESET
        113 => 103, // ECONNABORTED
        127 => 106, // EISCONN
        128 => 107, // ENOTCONN
        116 => 110, // ETIMEDOUT
        117 => 112, // EHOSTDOWN
        118 => 113, // EHOSTUNREACH
        120 => 114, // EALREADY
        119 => 115, // EINPROGRESS
        133 => 116, // ESTALE
        132 => 122, // EDQUOT
        140 => 125, // ECANCELED
        142 => 130, // EOWNERDEAD
        141 => 131, // ENOTRECOVERABLE
        _ => EIO,
    };
    -wire
}

/// Translate either a signed native/wire failure or its positive magnitude.
/// Unknown statuses become EIO rather than accidentally naming an unrelated
/// newlib error. This function must not be applied to an existing C errno.
pub const fn from_status(status: i64) -> i32 {
    let status = mochios_posix_protocol::status::normalize_failure(status) as i64;
    match status.unsigned_abs() {
        0x10001 => EFBIG, // POSIX wire STATUS_FILE_SIZE_LIMIT
        1..=14 | 16..=34 => status.unsigned_abs() as i32,
        35 => EDEADLK,
        36 => ENAMETOOLONG,
        37 => 46, // ENOLCK
        38 => ENOSYS,
        39 => 90, // ENOTEMPTY
        40 => 92, // ELOOP
        42 => 35, // ENOMSG
        43 => 36, // EIDRM
        60..=63 | 67 | 71 => status.unsigned_abs() as i32,
        72 => 74, // EMULTIHOP
        74 => 77, // EBADMSG
        75 => EOVERFLOW,
        84 => 138, // EILSEQ
        88 => 108, // ENOTSOCK
        89 => 121, // EDESTADDRREQ
        90 => 122, // EMSGSIZE
        91 => 107, // EPROTOTYPE
        92 => 109, // ENOPROTOOPT
        93 => 123, // EPROTONOSUPPORT
        // Native/wire 95 means the generic unsupported operation, not the
        // newlib socket-specific EOPNOTSUPP that happens to have this number.
        95 => ENOTSUP,
        96 => 96,   // EPFNOSUPPORT
        97 => 106,  // EAFNOSUPPORT
        98 => 112,  // EADDRINUSE
        99 => 125,  // EADDRNOTAVAIL
        100 => 115, // ENETDOWN
        101 => 114, // ENETUNREACH
        102 => 126, // ENETRESET
        103 => 113, // ECONNABORTED
        104 | 105 | 111 => status.unsigned_abs() as i32,
        106 => 127, // EISCONN
        107 => 128, // ENOTCONN
        110 => 116, // ETIMEDOUT
        112 => 117, // EHOSTDOWN
        113 => 118, // EHOSTUNREACH
        114 => 120, // EALREADY
        115 => 119, // EINPROGRESS
        116 => 133, // ESTALE
        122 => 132, // EDQUOT
        125 => 140, // ECANCELED
        130 => 142, // EOWNERDEAD
        131 => 141, // ENOTRECOVERABLE
        _ => EIO,
    }
}
