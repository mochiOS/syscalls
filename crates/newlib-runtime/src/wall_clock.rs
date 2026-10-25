//! newlib's wall-clock adapter. The checked clock reader remains native-fast.
use super::*;

#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub extern "C" fn gettimeofday(output: *mut Timeval, _timezone: *mut c_void) -> c_int {
    if output.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let mut instant = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_REALTIME is 1 in the SDK, independent of mnu's clock selectors.
    // clock_gettime validates native metadata, range and error propagation.
    if clock_gettime(1, &mut instant) != 0 {
        return -1;
    }
    let value = Timeval {
        tv_sec: instant.tv_sec,
        tv_usec: instant.tv_nsec / 1000,
    };
    let mut bytes = [0u8; core::mem::size_of::<Timeval>()];
    let seconds = core::mem::offset_of!(Timeval, tv_sec);
    let microseconds = core::mem::offset_of!(Timeval, tv_usec);
    bytes[seconds..seconds + 8].copy_from_slice(&value.tv_sec.to_ne_bytes());
    bytes[microseconds..microseconds + 8].copy_from_slice(&value.tv_usec.to_ne_bytes());
    // The obsolete timezone argument is ignored, including non-null values.
    // No process-independent timezone state is read or invented here.
    result_with_errno(user_copy::write(output.cast(), &bytes).map(|()| 0), -1)
}
