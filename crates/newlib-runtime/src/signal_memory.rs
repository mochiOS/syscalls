//! C signal metadata is copied at the boundary, never borrowed across IPC.
use super::*;
use mochios_posix_client::signal_context::SigInfo;

macro_rules! read_field {
    ($bytes:ident, $structure:ty, $field:ident, $integer:ty) => {{
        let start = core::mem::offset_of!($structure, $field);
        <$integer>::from_ne_bytes(
            $bytes[start..start + core::mem::size_of::<$integer>()]
                .try_into()
                .expect("C signal field"),
        )
    }};
}
macro_rules! write_field {
    ($bytes:ident, $structure:ty, $field:ident, $value:expr) => {{
        let start = core::mem::offset_of!($structure, $field);
        let value = $value.to_ne_bytes();
        $bytes[start..start + value.len()].copy_from_slice(&value);
    }};
}

pub(super) fn read_action(source: *const SignalAction) -> Result<SignalAction, c_int> {
    let mut bytes = [0; core::mem::size_of::<SignalAction>()];
    user_copy::read(source.cast(), &mut bytes)?;
    Ok(SignalAction {
        sa_flags: read_field!(bytes, SignalAction, sa_flags, c_int),
        sa_mask: read_field!(bytes, SignalAction, sa_mask, u64),
        handler: read_field!(bytes, SignalAction, handler, usize),
    })
}

pub(super) fn write_action(
    destination: *mut SignalAction,
    value: SignalAction,
) -> Result<(), c_int> {
    let mut bytes = [0; core::mem::size_of::<SignalAction>()];
    write_field!(bytes, SignalAction, sa_flags, value.sa_flags);
    write_field!(bytes, SignalAction, sa_mask, value.sa_mask);
    write_field!(bytes, SignalAction, handler, value.handler);
    user_copy::write(destination.cast(), &bytes)
}

pub(super) fn read_set(source: *const u64) -> Result<u64, c_int> {
    let mut bytes = [0; 8];
    user_copy::read(source.cast(), &mut bytes)?;
    Ok(u64::from_ne_bytes(bytes))
}

pub(super) fn write_set(destination: *mut u64, value: u64) -> Result<(), c_int> {
    user_copy::write(destination.cast(), &value.to_ne_bytes())
}

pub(super) fn write_selected(destination: *mut c_int, signal: c_int) -> Result<(), c_int> {
    user_copy::write(destination.cast(), &signal.to_ne_bytes())
}

pub(super) fn write_info(
    destination: *mut SigInfo,
    signal: u32,
    origin: posix_protocol::signal_origin::Origin,
) -> Result<(), c_int> {
    let value = SigInfo::from_origin(signal, origin).map_err(|error| match error {
        mochios_posix_client::signal_context::InfoError::Overflow => EOVERFLOW,
        _ => EIO,
    })?;
    if destination.is_null() {
        return Ok(());
    }
    let mut bytes = [0; core::mem::size_of::<SigInfo>()];
    write_field!(bytes, SigInfo, si_signo, value.si_signo);
    write_field!(bytes, SigInfo, si_code, value.si_code);
    // SAFETY: SigInfo::from_origin above initializes
    // the complete union as a pointer-sized integer, including its upper bytes.
    write_field!(bytes, SigInfo, si_value, unsafe {
        value.si_value.sival_ptr
    });
    write_field!(bytes, SigInfo, si_errno, value.si_errno);
    write_field!(bytes, SigInfo, si_pid, value.si_pid);
    write_field!(bytes, SigInfo, si_uid, value.si_uid);
    write_field!(bytes, SigInfo, reserved_uid, value.reserved_uid);
    write_field!(bytes, SigInfo, si_status, value.si_status);
    write_field!(bytes, SigInfo, si_addr, value.si_addr);
    user_copy::write(destination.cast(), &bytes)
}
