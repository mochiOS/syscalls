//! POSIX shared-memory FDs are local references to native Provider objects.
//! Names, permission checks and object identity remain in the userspace service.

use super::*;
use mochios_posix_protocol::shared_memory as wire;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn shm_open(pointer: *const c_char, flags: c_int, mode: u32) -> c_int {
    let result = (|| {
        let options =
            mochios_posix_client::shared_memory::newlib_open_options(flags).ok_or(EINVAL)?;
        if pointer.is_null() {
            return Err(EFAULT);
        }
        let name = unsafe { named_semaphore::name(pointer) }?;
        let limit = process_fd_limit()?;
        let reservation =
            PendingFdReservation(state().fds.reserve_from(0, limit).map_err(|_| EMFILE)?);
        let client = posix_client().map_err(map_posix_client_error)?;
        let opened = client
            .open_shared_memory(
                wire::Open {
                    options,
                    mode: if options & wire::CREATE != 0 { mode } else { 0 },
                    name,
                },
                close_object_handle,
            )
            .map_err(map_posix_client_error)?;
        let entry = object_entry(
            u64::from(opened.handle),
            opened.rights,
            FdKind::ObjectSharedMemory,
            (flags & 3) | O_CLOEXEC,
        );
        match state().fds.commit_reservation(&reservation.0, entry) {
            Ok(fd) => Ok(fd),
            Err(_) => {
                close_object_handle(opened.handle);
                Err(EIO)
            }
        }
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn shm_unlink(pointer: *const c_char) -> c_int {
    let result = (|| {
        if pointer.is_null() {
            return Err(EFAULT);
        }
        let name = unsafe { named_semaphore::name(pointer) }?;
        posix_client()
            .map_err(map_posix_client_error)?
            .unlink_shared_memory(name, close_object_handle)
            .map_err(map_posix_client_error)?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

pub(super) fn truncate(entry: FdEntry, length: u64) -> Result<(), c_int> {
    if !mochios_posix_client::fd::access_allows_write(entry.handle.open_flags as u32) {
        return Err(EBADF);
    }
    let bytes = length.to_le_bytes();
    let written = syscall_errno(syscall::raw_syscall6(
        syscall::SyscallNumber::HandleControl,
        entry.handle.lower_handle,
        wire::CONTROL_RESIZE,
        bytes.as_ptr() as u64,
        bytes.len() as u64,
        0,
        0,
    ))?;
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

pub(super) struct MappingBacking(pub u32);
impl Drop for MappingBacking {
    fn drop(&mut self) {
        close_object_handle(self.0);
    }
}

pub(super) fn mapping(entry: FdEntry, writable: bool) -> Result<MappingBacking, c_int> {
    let descriptor = ObjectHandleAttachment {
        handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
        rights: entry.rights,
    };
    let backing = posix_client()
        .map_err(map_posix_client_error)?
        .shared_memory_backing(descriptor, writable, close_object_handle)
        .map_err(map_posix_client_error)?;
    Ok(MappingBacking(backing.handle))
}
