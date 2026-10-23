//! Descriptor-facing adapters; mutable flags belong to shared descriptions,
//! never to copies of their metadata in this process's FD table.
use super::*;

enum StatusSource {
    Local(c_int),
    Native(fd_lease::Lease),
}

/// Keep descriptor-local updates atomic, but never hold STATE across an OFD
/// provider call. The captured native reference remains pinned across callbacks.
pub(super) fn status(fd: c_int, command: c_int, argument: c_int) -> Result<c_int, c_int> {
    io_resources::with(
        || {
            let mut state = state();
            let entry = state.fds.get(fd).ok_or(EBADF)?;
            if matches!(
                entry.handle.kind,
                FdKind::Unused | FdKind::Stdin | FdKind::Stdout | FdKind::Stderr
            ) {
                return Ok(StatusSource::Local(if command == F_GETFL {
                    entry.handle.open_flags
                } else {
                    state.fds.get_mut(fd).ok_or(EBADF)?.handle.open_flags = argument;
                    0
                }));
            }
            Ok(StatusSource::Native(fd_lease::Lease::new(entry)?))
        },
        |source| match source {
            StatusSource::Local(value) => Ok(*value),
            StatusSource::Native(entry) if command == F_GETFL => get_status_flags(**entry),
            StatusSource::Native(entry) => set_status_flags(**entry, argument).map(|_| 0),
        },
    )
}

fn get_status_flags(entry: FdEntry) -> Result<c_int, c_int> {
    match entry.handle.kind {
        FdKind::ObjectSocket | FdKind::ObjectDatagram => socket::get_status_flags(entry),
        FdKind::ObjectSharedMemory => shared_memory::get_status_flags(entry),
        FdKind::ObjectFile | FdKind::ObjectDirectory => file_description_flags::get(entry),
        FdKind::ObjectSpecial => {
            let flags = posix_client()
                .map_err(map_posix_client_error)?
                .get_status_flags(ObjectHandleAttachment {
                    handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                    rights: entry.rights,
                })
                .map_err(map_posix_client_error)?;
            Ok((entry.handle.open_flags & 3) | newlib_mutable_status_flags(flags))
        }
        FdKind::ObjectStreamRead
        | FdKind::ObjectStreamWrite
        | FdKind::ObjectPty
        | FdKind::ObjectTerminalFile => {
            let options = syscall_errno(syscall::raw_syscall1(
                syscall::SyscallNumber::HandleOptionsGet,
                entry.handle.lower_handle,
            ))?;
            Ok((entry.handle.open_flags & 3)
                | if options & syscall::HANDLE_OPTION_NONBLOCKING != 0 {
                    O_NONBLOCK
                } else {
                    0
                })
        }
        _ => Err(EINVAL),
    }
}

fn set_status_flags(entry: FdEntry, flags: c_int) -> Result<(), c_int> {
    match entry.handle.kind {
        FdKind::ObjectSocket | FdKind::ObjectDatagram => socket::set_status_flags(entry, flags),
        FdKind::ObjectSharedMemory => shared_memory::set_status_flags(entry, flags),
        FdKind::ObjectFile | FdKind::ObjectDirectory => file_description_flags::set(entry, flags),
        FdKind::ObjectSpecial => posix_client()
            .map_err(map_posix_client_error)?
            .set_status_flags(
                ObjectHandleAttachment {
                    handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                    rights: entry.rights,
                },
                posix_mutable_status_flags(flags),
            )
            .map_err(map_posix_client_error),
        FdKind::ObjectStreamRead
        | FdKind::ObjectStreamWrite
        | FdKind::ObjectPty
        | FdKind::ObjectTerminalFile => {
            if flags & !(O_NONBLOCK | 3) != 0 {
                return Err(EINVAL);
            }
            syscall_errno(syscall::raw_syscall2(
                syscall::SyscallNumber::HandleOptionsSet,
                entry.handle.lower_handle,
                if flags & O_NONBLOCK != 0 {
                    syscall::HANDLE_OPTION_NONBLOCKING
                } else {
                    0
                },
            ))
            .map(|_| ())
        }
        _ => Err(EINVAL),
    }
}

fn set_nonblocking(fd: c_int, enabled: bool) -> Result<c_int, c_int> {
    io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            let mask = posix_protocol::OPEN_NONBLOCK;
            let flags = if enabled { mask } else { 0 };
            match entry.handle.kind {
                FdKind::ObjectSocket | FdKind::ObjectDatagram => {
                    socket::set_status_flags(**entry, if enabled { O_NONBLOCK } else { 0 })?;
                }
                FdKind::ObjectSharedMemory => {
                    shared_memory::update_status_flags(**entry, mask, flags)?
                }
                FdKind::ObjectFile | FdKind::ObjectDirectory => {
                    let mask = mochios_filesystem_protocol::OPEN_STATUS_NONBLOCK;
                    file_description_flags::update(**entry, mask, if enabled { mask } else { 0 })?;
                }
                FdKind::ObjectSpecial => {
                    posix_client()
                        .map_err(map_posix_client_error)?
                        .update_status_flags(
                            ObjectHandleAttachment {
                                handle: u32::try_from(entry.handle.lower_handle)
                                    .map_err(|_| EBADF)?,
                                rights: entry.rights,
                            },
                            mask,
                            flags,
                            close_object_handle,
                        )
                        .map_err(map_posix_client_error)?;
                }
                FdKind::ObjectStreamRead
                | FdKind::ObjectStreamWrite
                | FdKind::ObjectPty
                | FdKind::ObjectTerminalFile => {
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
        },
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn __mochios_fd_set_nonblocking(fd: c_int, enabled: c_int) -> c_int {
    result_with_errno(set_nonblocking(fd, enabled != 0), -1)
}
