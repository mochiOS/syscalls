//! C time/accounting values are explicit byte formats at the libc boundary.
use super::*;

pub(super) fn read_timespec(source: *const Timespec) -> Result<Timespec, c_int> {
    let mut bytes = [0; core::mem::size_of::<Timespec>()];
    user_copy::read(source.cast(), &mut bytes)?;
    let seconds = core::mem::offset_of!(Timespec, tv_sec);
    let nanoseconds = core::mem::offset_of!(Timespec, tv_nsec);
    Ok(Timespec {
        tv_sec: i64::from_ne_bytes(
            bytes[seconds..seconds + 8]
                .try_into()
                .expect("time seconds"),
        ),
        tv_nsec: i64::from_ne_bytes(
            bytes[nanoseconds..nanoseconds + 8]
                .try_into()
                .expect("time nanoseconds"),
        ),
    })
}

macro_rules! field {
    ($bytes:ident, $structure:ty, $value:ident, $field:ident) => {{
        let value = $value.$field.to_ne_bytes();
        let offset = core::mem::offset_of!($structure, $field);
        $bytes[offset..offset + value.len()].copy_from_slice(&value);
    }};
}

pub(super) fn write_timespec(destination: *mut Timespec, value: Timespec) -> Result<(), c_int> {
    let mut bytes = [0; core::mem::size_of::<Timespec>()];
    field!(bytes, Timespec, value, tv_sec);
    field!(bytes, Timespec, value, tv_nsec);
    user_copy::write(destination.cast(), &bytes)
}

pub(super) fn write_accounting(destination: *mut Tms, value: Tms) -> Result<(), c_int> {
    let mut bytes = [0; core::mem::size_of::<Tms>()];
    field!(bytes, Tms, value, tms_utime);
    field!(bytes, Tms, value, tms_stime);
    field!(bytes, Tms, value, tms_cutime);
    field!(bytes, Tms, value, tms_cstime);
    user_copy::write(destination.cast(), &bytes)
}
