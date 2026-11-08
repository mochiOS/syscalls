//! C signatures paired with the SDK io-abi.c header checks. Keep the runtime
//! implementation and the installed C declarations on the same calling ABI.
use super::{c_char, c_int, c_void, credentials};

const _: extern "C" fn(c_int, *mut c_void, usize) -> isize = super::read;
const _: extern "C" fn(c_int, *const c_void, usize) -> isize = super::write;
const _: unsafe extern "C" fn(*const c_char, c_int, ...) -> c_int = super::open;
const _: unsafe extern "C" fn(*const c_char, c_int, ...) -> c_int = super::_open;
const _: unsafe extern "C" fn(c_int, *const c_char, c_int, ...) -> c_int = super::openat;
const _: extern "C" fn(*const c_char, credentials::Id, credentials::Id) -> c_int = super::chown;
const _: extern "C" fn(*const c_char, credentials::Id, credentials::Id) -> c_int = super::lchown;
const _: extern "C" fn(c_int, credentials::Id, credentials::Id) -> c_int = super::fchown;
const _: extern "C" fn(c_int, *const c_char, credentials::Id, credentials::Id, c_int) -> c_int =
    super::fchownat;
const _: extern "C" fn(*const c_char, u32) -> c_int = super::mkdir;
const _: extern "C" fn(*const c_char, u32) -> c_int = super::_mkdir;
const _: extern "C" fn(c_int, *const c_char, u32) -> c_int = super::mkdirat;
