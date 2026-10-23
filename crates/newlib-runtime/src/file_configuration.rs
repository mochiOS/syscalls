//! Descriptor configuration over a retained native object, never a pathname
//! reopen or a POSIX service request. The FD lease spans the whole observation.
use super::*;
use mochios_filesystem_protocol::object_limits as wire;

// Newlib sys/unistd.h selectors, interpreted only in userspace.
const PC_LINK_MAX: c_int = 0;
const PC_NAME_MAX: c_int = 3;
const PC_PATH_MAX: c_int = 4;
const PC_PIPE_BUF: c_int = 5;

fn limits(entry: FdEntry) -> Result<wire::Limits, c_int> {
    let mut bytes = [0; wire::RESPONSE_LEN];
    let operation = if entry.rights & syscall::HANDLE_RIGHT_READ != 0 {
        syscall::SyscallNumber::HandleQuery
    } else {
        syscall::SyscallNumber::HandleControl
    };
    let count = syscall_errno(syscall::raw_syscall6(
        operation,
        entry.handle.lower_handle,
        wire::GET,
        0,
        0,
        bytes.as_mut_ptr() as u64,
        bytes.len() as u64,
    ))?;
    if count != bytes.len() as u64 {
        return Err(EIO);
    }
    wire::Limits::decode(&bytes).ok_or(EIO)
}

fn query(entry: FdEntry, name: c_int) -> Result<CLong, c_int> {
    if !(0..=20).contains(&name) {
        return Err(EINVAL);
    }
    if name == PC_PIPE_BUF {
        return if matches!(
            entry.handle.kind,
            FdKind::ObjectStreamRead | FdKind::ObjectStreamWrite
        ) {
            Ok(mochios_posix_client::stream::PIPE_BUF as CLong)
        } else {
            Err(ENOTSUP)
        };
    }
    if !matches!(name, PC_LINK_MAX | PC_NAME_MAX | PC_PATH_MAX)
        || !matches!(
            entry.handle.kind,
            FdKind::ObjectFile | FdKind::ObjectDirectory | FdKind::ObjectSpecial
        )
    {
        return Err(ENOTSUP);
    }
    filesystem_value(limits(entry)?, name)
}

pub(super) fn filesystem_selector(name: c_int) -> Result<(), c_int> {
    match name {
        PC_LINK_MAX | PC_NAME_MAX | PC_PATH_MAX => Ok(()),
        0..=20 => Err(ENOTSUP),
        _ => Err(EINVAL),
    }
}

pub(super) fn filesystem_value(limits: wire::Limits, name: c_int) -> Result<CLong, c_int> {
    filesystem_selector(name)?;
    let value = match name {
        PC_LINK_MAX => limits.link_count_max,
        PC_NAME_MAX => limits.name_bytes_max,
        PC_PATH_MAX => limits
            .path_bytes_max
            .min(posix_protocol::MAX_PATH_LEN as u32),
        _ => unreachable!(),
    };
    if value == 0 {
        return Err(EIO);
    }
    // Both the owner and POSIX wire bound pathname bytes without a NUL.
    Ok(CLong::from(value) + CLong::from(name == PC_PATH_MAX))
}

#[unsafe(no_mangle)]
pub extern "C" fn fpathconf(fd: c_int, name: c_int) -> CLong {
    result_with_errno(
        io_resources::with(|| with_fd_entry(fd), |entry| query(**entry, name)),
        -1,
    )
}
