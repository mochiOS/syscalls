//! Fault-safe C readiness metadata; FD/Handle ownership stays in the caller.
use super::*;

macro_rules! read_field {
    ($bytes:ident, $structure:ty, $field:ident, $integer:ty) => {{
        let start = core::mem::offset_of!($structure, $field);
        <$integer>::from_ne_bytes(
            $bytes[start..start + core::mem::size_of::<$integer>()]
                .try_into()
                .expect("C field fits its structure"),
        )
    }};
}

pub(super) fn read_mask(source: *const u64) -> Result<u64, c_int> {
    let mut bytes = [0; 8];
    user_copy::read(source.cast(), &mut bytes)?;
    Ok(u64::from_ne_bytes(bytes))
}

pub(super) fn read_timeval(source: *const Timeval) -> Result<Timeval, c_int> {
    let mut bytes = [0; core::mem::size_of::<Timeval>()];
    user_copy::read(source.cast(), &mut bytes)?;
    Ok(Timeval {
        tv_sec: read_field!(bytes, Timeval, tv_sec, i64),
        tv_usec: read_field!(bytes, Timeval, tv_usec, i64),
    })
}

pub(super) fn read_timespec(source: *const NewlibTimespec) -> Result<NewlibTimespec, c_int> {
    let mut bytes = [0; core::mem::size_of::<NewlibTimespec>()];
    user_copy::read(source.cast(), &mut bytes)?;
    Ok(NewlibTimespec {
        tv_sec: read_field!(bytes, NewlibTimespec, tv_sec, i64),
        tv_nsec: read_field!(bytes, NewlibTimespec, tv_nsec, i64),
    })
}

fn poll_address(base: usize, index: usize) -> Result<usize, c_int> {
    base.checked_add(
        index
            .checked_mul(core::mem::size_of::<PollFd>())
            .ok_or(EFAULT)?,
    )
    .ok_or(EFAULT)
}

pub(super) fn read_pollfd(source: *const PollFd, index: usize) -> Result<PollFd, c_int> {
    let address = poll_address(source as usize, index)?;
    let mut bytes = [0; core::mem::size_of::<PollFd>()];
    user_copy::read(address as *const u8, &mut bytes)?;
    Ok(PollFd {
        fd: read_field!(bytes, PollFd, fd, c_int),
        events: read_field!(bytes, PollFd, events, i16),
        revents: read_field!(bytes, PollFd, revents, i16),
    })
}

pub(super) fn write_pollfd(
    destination: *mut PollFd,
    index: usize,
    value: PollFd,
) -> Result<(), c_int> {
    let address = poll_address(destination as usize, index)?;
    let mut bytes = [0; core::mem::size_of::<PollFd>()];
    macro_rules! field {
        ($field:ident) => {{
            let start = core::mem::offset_of!(PollFd, $field);
            let value = value.$field.to_ne_bytes();
            bytes[start..start + value.len()].copy_from_slice(&value);
        }};
    }
    field!(fd);
    field!(events);
    field!(revents);
    user_copy::write(address as *mut u8, &bytes)
}
