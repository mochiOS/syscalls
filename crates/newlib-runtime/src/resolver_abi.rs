//! BSD resolver compatibility. Native endpoints and job snapshots remain the
//! authority; no resolv.conf server override or direct socket path is added.
use super::netdb_backend::{Backend, native::Native};
use super::*;
use mochios_posix_client::{netdb::Error, resolver_packet as packet};

/// Per-thread h_errno storage, sharing the runtime's thread-slot lifetime.
/// Like errno, the returned pointer is valid only for the calling thread.
#[unsafe(no_mangle)]
pub extern "C" fn __h_errno_location() -> *mut c_int {
    let (_, control) = register_thread_control().unwrap_or_else(|| process_exit(127));
    control.resolver_error.as_ptr().cast()
}
fn h_error(value: c_int) {
    // No Rust reference to the externally accessible thread-local scalar.
    unsafe { __h_errno_location().write(value) };
}
fn dns_error(error: Error) -> c_int {
    h_error(match error {
        Error::System(mochios_posix_client::resolver::NO_DATA_STATUS) => 4, // NO_DATA
        Error::NoName => 1,                                                 // HOST_NOT_FOUND
        Error::Again => 2,                                                  // TRY_AGAIN
        _ => 3,                                                             // NO_RECOVERY
    });
    match error {
        Error::System(mochios_posix_client::resolver::NO_DATA_STATUS) => ENOENT,
        Error::System(status) => mochios_posix_client::newlib_errno::from_status(i64::from(status)),
        Error::Memory => ENOMEM,
        Error::Again => EAGAIN,
        Error::NoName => ENOENT,
        _ => EIO,
    }
}

/// Query one supported IN-class record type through native DNS authority.
/// Returns the complete reply size, possibly larger than answer_length; the
/// copied prefix then has TC set. A caller must resize/retry before parsing.
/// Replies contain validated data and CNAME paths, TTL zero, and no DNSSEC claim.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn res_query(
    name: *const c_char,
    class: c_int,
    kind: c_int,
    answer: *mut u8,
    answer_length: c_int,
) -> c_int {
    pthread_testcancel();
    h_error(3);
    let result = match packet::query_kind(class, kind) {
        Ok(query_kind) => resolver_transaction::query(
            Backend::new(Native::for_kind(query_kind)),
            name,
            class,
            kind,
            answer,
            answer_length,
            dns_error,
        ),
        Err(_) => Err(ENOTSUP),
    };
    if result.is_ok() {
        h_error(0);
    }
    let value = result_with_errno(result, -1);
    pthread_testcancel();
    value
}

/// Expand one compressed name in a bounded caller-owned DNS packet. All input
/// is copied with fault-aware MemoryCopy before parsing; output includes NUL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dn_expand(
    message: *const u8,
    end: *const u8,
    compressed: *const u8,
    destination: *mut c_char,
    destination_length: c_int,
) -> c_int {
    result_with_errno(
        resolver_transaction::expand(message, end, compressed, destination, destination_length),
        -1,
    )
}
