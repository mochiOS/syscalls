//! POSIX shared-memory FDs are local references to native Provider objects.
//! Names, permission checks and object identity remain in the userspace service.

use super::*;
use mochios_posix_protocol::shared_memory as wire;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn shm_open(pointer: *const c_char, flags: c_int, mode: u32) -> c_int {
    result_with_errno(shared_memory_namespace::open(pointer, flags, mode), -1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn shm_unlink(pointer: *const c_char) -> c_int {
    result_with_errno(shared_memory_namespace::unlink(pointer), -1)
}

pub(super) fn truncate(entry: FdEntry, length: u64) -> Result<(), c_int> {
    if !mochios_posix_client::fd::access_allows_write(entry.handle.open_flags as u32) {
        return Err(EBADF);
    }
    let limit = resource_policy::read(posix_protocol::RLIMIT_FSIZE)?;
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&length.to_le_bytes());
    bytes[8..].copy_from_slice(&limit.soft.to_le_bytes());
    // Current size and growth admission are selected by the Provider under
    // its shared description/namespace lock, never by a client-side stat.
    let result = syscall::raw_syscall6(
        syscall::SyscallNumber::HandleControl,
        entry.handle.lower_handle,
        wire::CONTROL_RESIZE_BOUNDED,
        bytes.as_ptr() as u64,
        bytes.len() as u64,
        0,
        0,
    );
    if result.raw() == mnu_abi::provider::STATUS_BOUND_REACHED as u64 {
        generate_thread_signal(posix_protocol::SIGNAL_XFSZ)?;
        return Err(EFBIG);
    }
    let written = syscall_errno(result)?;
    if written != 0 {
        return Err(EIO);
    }
    Ok(())
}

pub(super) fn stat(entry: FdEntry) -> Result<NewlibStat, c_int> {
    let mut bytes = [0; posix_protocol::FILE_STATUS_LEN];
    let length = syscall_errno(syscall::raw_syscall6(
        syscall::SyscallNumber::HandleControl,
        entry.handle.lower_handle,
        wire::CONTROL_STAT,
        0,
        0,
        bytes.as_mut_ptr() as u64,
        bytes.len() as u64,
    ))?;
    if length as usize != bytes.len() {
        return Err(EIO);
    }
    let status = posix_protocol::decode_file_status(&bytes).map_err(|_| EIO)?;
    translate_posix_stat(&status)
}

pub(super) fn get_status_flags(entry: FdEntry) -> Result<c_int, c_int> {
    let mut bytes = [0; 4];
    let length = syscall_errno(syscall::raw_syscall6(
        syscall::SyscallNumber::HandleControl,
        entry.handle.lower_handle,
        wire::CONTROL_GET_FLAGS,
        0,
        0,
        bytes.as_mut_ptr() as u64,
        bytes.len() as u64,
    ))?;
    if length != 4 {
        return Err(EIO);
    }
    let flags = u32::from_le_bytes(bytes);
    if flags & !(posix_protocol::OPEN_APPEND | posix_protocol::OPEN_NONBLOCK) != 0 {
        return Err(EIO);
    }
    Ok((entry.handle.open_flags & 3) | newlib_mutable_status_flags(flags))
}

pub(super) fn set_status_flags(entry: FdEntry, flags: c_int) -> Result<(), c_int> {
    let bytes = posix_mutable_status_flags(flags).to_le_bytes();
    let length = syscall_errno(syscall::raw_syscall6(
        syscall::SyscallNumber::HandleControl,
        entry.handle.lower_handle,
        wire::CONTROL_SET_FLAGS,
        bytes.as_ptr() as u64,
        bytes.len() as u64,
        0,
        0,
    ))?;
    if length != 0 {
        return Err(EIO);
    }
    Ok(())
}

pub(super) fn update_status_flags(entry: FdEntry, mask: u32, flags: u32) -> Result<(), c_int> {
    let mut bytes = [0; posix_protocol::FILE_FLAGS_UPDATE_PAYLOAD_LEN];
    posix_protocol::encode_file_flags_update(mask, flags, &mut bytes).map_err(|_| EINVAL)?;
    let length = syscall_errno(syscall::raw_syscall6(
        syscall::SyscallNumber::HandleControl,
        entry.handle.lower_handle,
        wire::CONTROL_UPDATE_FLAGS,
        bytes.as_ptr() as u64,
        bytes.len() as u64,
        0,
        0,
    ))?;
    if length != 0 {
        return Err(EIO);
    }
    Ok(())
}
