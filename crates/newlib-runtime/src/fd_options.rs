//! Descriptor-facing adapters; mutable flags belong to shared descriptions,
//! never to copies of their metadata in this process's FD table.
use super::*;

fn set_nonblocking(fd: c_int, enabled: bool) -> Result<c_int, c_int> {
    let entry = with_fd_entry(fd)?;
    let mask = posix_protocol::OPEN_NONBLOCK;
    let flags = if enabled { mask } else { 0 };
    match entry.handle.kind {
        FdKind::ObjectSocket | FdKind::ObjectDatagram => {
            socket::set_status_flags(entry, if enabled { O_NONBLOCK } else { 0 })?;
        }
        FdKind::ObjectSharedMemory => shared_memory::update_status_flags(entry, mask, flags)?,
        FdKind::ObjectFile | FdKind::ObjectSpecial | FdKind::ObjectDirectory => {
            posix_client()
                .map_err(map_posix_client_error)?
                .update_status_flags(
                    ObjectHandleAttachment {
                        handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                        rights: entry.rights,
                    },
                    mask,
                    flags,
                    close_object_handle,
                )
                .map_err(map_posix_client_error)?;
        }
        FdKind::ObjectStreamRead | FdKind::ObjectStreamWrite | FdKind::ObjectPty => {
            // Native streams currently have exactly one generic mutable option.
            // There is no client-side read/modify/write race between aliases.
            const _: () =
                assert!(syscall::HANDLE_OPTIONS_ALL == syscall::HANDLE_OPTION_NONBLOCKING);
            syscall_errno(syscall::raw_syscall2(
                syscall::SyscallNumber::HandleOptionsSet,
                entry.handle.lower_handle,
                if enabled {
                    syscall::HANDLE_OPTION_NONBLOCKING
                } else {
                    0
                },
            ))?;
        }
        _ => return Err(ENOTTY),
    }
    Ok(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn __mochios_fd_set_nonblocking(fd: c_int, enabled: c_int) -> c_int {
    result_with_errno(set_nonblocking(fd, enabled != 0), -1)
}
