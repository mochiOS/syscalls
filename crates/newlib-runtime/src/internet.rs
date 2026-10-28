//! C Internet address APIs. Application pointers are snapshots/checked writes,
//! never Rust references. These pure conversions require no service authority.
use super::*;
use mochios_posix_client::internet::{Address, INET6_ADDRSTRLEN, address_length};

#[repr(C, align(4))]
pub struct In6Address([u8; 16]);
#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static in6addr_any: In6Address = In6Address([0; 16]);
#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static in6addr_loopback: In6Address =
    In6Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

fn errno(status: i32) -> c_int {
    mochios_posix_client::newlib_errno::from_status(i64::from(status))
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn inet_pton(
    family: c_int,
    source: *const c_char,
    destination: *mut c_void,
) -> c_int {
    let result = (|| {
        address_length(family).map_err(errno)?;
        let mut text = [0; INET6_ADDRSTRLEN - 1];
        let length = match user_copy::capture_text(source, &mut text, ENAMETOOLONG) {
            Ok(length) => length,
            Err(ENAMETOOLONG) => return Ok(0),
            Err(error) => return Err(error),
        };
        let Some(address) = Address::parse(family, &text[..length]).map_err(errno)? else {
            return Ok(0);
        };
        user_copy::write(destination.cast(), address.octets())?;
        Ok(1)
    })();
    result_with_errno(result, -1)
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn inet_ntop(
    family: c_int,
    source: *const c_void,
    destination: *mut c_char,
    capacity: u32,
) -> *const c_char {
    let result = (|| {
        let length = address_length(family).map_err(errno)?;
        let mut bytes = [0; 16];
        user_copy::read(source.cast(), &mut bytes[..length])?;
        let address = Address::from_octets(family, &bytes[..length]).map_err(errno)?;
        let mut text = [0; INET6_ADDRSTRLEN];
        let length = address
            .format(&mut text[..INET6_ADDRSTRLEN - 1])
            .map_err(errno)?;
        if (capacity as usize) <= length {
            return Err(errno(-28));
        }
        text[length] = 0;
        user_copy::write(destination.cast(), &text[..length + 1])?;
        Ok(destination.cast_const())
    })();
    result_with_errno(result, core::ptr::null())
}
