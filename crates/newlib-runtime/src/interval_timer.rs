//! Process elapsed-time timers. CPU-time timers require separate accounting.
use super::*;
use posix_protocol::interval_timer::Value;

#[repr(C)]
pub(super) struct Itimerval {
    interval: Timeval,
    value: Timeval,
}

fn check_kind(which: c_int) -> Result<(), c_int> {
    match which {
        0 => Ok(()),
        1 | 2 => Err(ENOSYS),
        _ => Err(EINVAL),
    }
}

fn duration(seconds: i64, microseconds: i64) -> Result<u64, c_int> {
    if seconds < 0 || !(0..1_000_000).contains(&microseconds) {
        return Err(EINVAL);
    }
    (seconds as u64)
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(microseconds as u64 * 1_000))
        .ok_or(EINVAL)
}

fn read(source: *const Itimerval) -> Result<Value, c_int> {
    let mut bytes = [0; core::mem::size_of::<Itimerval>()];
    user_copy::read(source.cast(), &mut bytes)?;
    let field = |base, offset| {
        let start = base + offset;
        i64::from_ne_bytes(bytes[start..start + 8].try_into().unwrap())
    };
    let time = |base| {
        duration(
            field(base, core::mem::offset_of!(Timeval, tv_sec)),
            field(base, core::mem::offset_of!(Timeval, tv_usec)),
        )
    };
    Ok(Value {
        interval_ns: time(core::mem::offset_of!(Itimerval, interval))?,
        remaining_ns: time(core::mem::offset_of!(Itimerval, value))?,
    })
}

fn write(destination: *mut Itimerval, value: Value) -> Result<(), c_int> {
    let mut bytes = [0; core::mem::size_of::<Itimerval>()];
    for (base, ns) in [
        (
            core::mem::offset_of!(Itimerval, interval),
            value.interval_ns,
        ),
        (core::mem::offset_of!(Itimerval, value), value.remaining_ns),
    ] {
        // An armed sub-microsecond remainder must not look disarmed in C.
        let us = ns.div_ceil(1_000);
        for (offset, number) in [
            (
                core::mem::offset_of!(Timeval, tv_sec),
                (us / 1_000_000) as i64,
            ),
            (
                core::mem::offset_of!(Timeval, tv_usec),
                (us % 1_000_000) as i64,
            ),
        ] {
            bytes[base + offset..base + offset + 8].copy_from_slice(&number.to_ne_bytes());
        }
    }
    user_copy::write(destination.cast(), &bytes)
}

#[unsafe(no_mangle)]
pub extern "C" fn getitimer(which: c_int, current: *mut Itimerval) -> c_int {
    let result = (|| {
        check_kind(which)?;
        if current.is_null() {
            return Err(EFAULT);
        }
        let value = posix_client()
            .map_err(map_posix_client_error)?
            .real_timer()
            .map_err(map_posix_client_error)?;
        write(current, value)?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn setitimer(
    which: c_int,
    replacement: *const Itimerval,
    previous: *mut Itimerval,
) -> c_int {
    let result = (|| {
        check_kind(which)?;
        // Import both timeval records before IPC or any potentially aliased
        // output. C pointers and struct padding never enter the wire message.
        let value = read(replacement)?;
        let old = posix_client()
            .map_err(map_posix_client_error)?
            .set_real_timer(value)
            .map_err(|error| match map_posix_client_error(error) {
                EOVERFLOW => EINVAL,
                error => error,
            })?;
        if !previous.is_null() {
            write(previous, old)?;
        }
        Ok(0)
    })();
    result_with_errno(result, -1)
}
