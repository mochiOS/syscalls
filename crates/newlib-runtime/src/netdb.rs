//! Public C name-service boundary. The transaction owns all temporary native
//! resources before performing I/O; only a complete C list is published.
use super::netdb_backend::{Backend, native::Native};
use super::netdb_memory::AddrInfo;
use super::*;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const AddrInfo,
    result: *mut *mut AddrInfo,
) -> c_int {
    pthread_testcancel();
    let status = netdb_abi::getaddrinfo(Backend::new(Native::new()), node, service, hints, result);
    // A cancelled failed transaction has already retired its private prefix.
    // Do not cancel after successfully publishing ownership to the caller.
    if status != 0 {
        pthread_testcancel();
    }
    status
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getnameinfo(
    address: *const c_void,
    address_length: u32,
    host: *mut c_char,
    host_length: u32,
    service: *mut c_char,
    service_length: u32,
    flags: c_int,
) -> c_int {
    pthread_testcancel();
    let status = netdb_abi::getnameinfo(
        Backend::new(Native::new()),
        address,
        address_length,
        host,
        host_length,
        service,
        service_length,
        flags,
    );
    if status != 0 {
        pthread_testcancel();
    }
    status
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn freeaddrinfo(head: *mut AddrInfo) {
    if let Err(mochios_posix_client::netdb::Error::System(status)) =
        unsafe { netdb_memory::release(head) }
    {
        set_errno(mochios_posix_client::newlib_errno::from_status(i64::from(
            status,
        )));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gai_strerror(code: c_int) -> *const c_char {
    netdb_memory::error_text(code).as_ptr().cast()
}
