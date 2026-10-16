//! C socket-control buffers are copied, never borrowed as application objects.
use super::*;

pub(super) fn read_length(source: *const u32) -> Result<u32, c_int> {
    let mut bytes = [0; 4];
    user_copy::read(source.cast(), &mut bytes)?;
    Ok(u32::from_ne_bytes(bytes))
}

pub(super) fn read_timeout(source: *const c_void) -> Result<Timeval, c_int> {
    let mut bytes = [0; core::mem::size_of::<Timeval>()];
    user_copy::read(source.cast(), &mut bytes)?;
    let seconds = core::mem::offset_of!(Timeval, tv_sec);
    let microseconds = core::mem::offset_of!(Timeval, tv_usec);
    Ok(Timeval {
        tv_sec: i64::from_ne_bytes(
            bytes[seconds..seconds + 8]
                .try_into()
                .expect("timeval seconds"),
        ),
        tv_usec: i64::from_ne_bytes(
            bytes[microseconds..microseconds + 8]
                .try_into()
                .expect("timeval microseconds"),
        ),
    })
}

pub(super) fn write_output(
    destination: *mut c_void,
    length: *mut u32,
    bytes: &[u8],
    reported_length: u32,
) -> Result<(), c_int> {
    user_copy::write(destination.cast(), bytes)?;
    user_copy::write(length.cast(), &reported_length.to_ne_bytes())
}
