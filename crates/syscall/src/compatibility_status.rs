//! Userspace service-protocol statuses retained by compatibility callers.
//! These are not mnu syscall error categories; use NativeError for mechanisms.
//! Provider/service payloads may carry these signed statuses opaquely.

pub const ENOENT: u64 = (-2i64) as u64;
pub const EIO: u64 = (-5i64) as u64;
pub const EAGAIN: u64 = (-11i64) as u64;
pub const ENOMEM: u64 = (-12i64) as u64;
pub const EACCES: u64 = (-13i64) as u64;
pub const EINVAL: u64 = (-22i64) as u64;
