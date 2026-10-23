//! Call the retained provider directly; no POSIX endpoint or Handle transfer.
//! The enclosing FD lease keeps this exact description alive during callbacks.
use super::*;
use mochios_filesystem_protocol::{self as filesystem, description_flags as wire};

const O_APPEND: c_int = 0x0008; // newlib _FAPPEND, not a native option bit.

pub(super) fn get(entry: FdEntry) -> Result<c_int, c_int> {
    let mut bytes = [0u8; 4];
    // A write-only description has no READ authority. Its existing CONTROL
    // authority permits the explicitly implemented observation instead.
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
    let flags = u32::from_le_bytes(bytes);
    if count != bytes.len() as u64 || flags & !filesystem::OPEN_STATUS_FLAGS_ALL != 0 {
        return Err(EIO);
    }
    Ok((entry.handle.open_flags & 3)
        | if flags & filesystem::OPEN_STATUS_APPEND != 0 {
            O_APPEND
        } else {
            0
        }
        | if flags & filesystem::OPEN_STATUS_NONBLOCK != 0 {
            O_NONBLOCK
        } else {
            0
        })
}

pub(super) fn update(entry: FdEntry, mask: u32, flags: u32) -> Result<(), c_int> {
    let bytes = wire::encode_update(mask, flags).ok_or(EINVAL)?;
    let count = syscall_errno(syscall::raw_syscall6(
        syscall::SyscallNumber::HandleControl,
        entry.handle.lower_handle,
        wire::UPDATE,
        bytes.as_ptr() as u64,
        bytes.len() as u64,
        0,
        0,
    ))?;
    if count != 0 {
        return Err(EIO);
    }
    Ok(())
}

pub(super) fn set(entry: FdEntry, flags: c_int) -> Result<(), c_int> {
    update(
        entry,
        filesystem::OPEN_STATUS_FLAGS_ALL,
        (if flags & O_APPEND != 0 {
            filesystem::OPEN_STATUS_APPEND
        } else {
            0
        }) | (if flags & O_NONBLOCK != 0 {
            filesystem::OPEN_STATUS_NONBLOCK
        } else {
            0
        }),
    )
}
