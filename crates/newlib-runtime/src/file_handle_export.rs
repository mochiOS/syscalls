//! Export only a pinned local descriptor; never look up a foreign PID or FD.
use super::*;
use fd_creation::PendingHandles;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ExportedFdHandle {
    pub handle: u32,
    pub reserved: u32,
    pub rights: u64,
    pub metadata: u64,
}

const _: () = {
    assert!(core::mem::size_of::<ExportedFdHandle>() == 24);
    assert!(core::mem::offset_of!(ExportedFdHandle, handle) == 0);
    assert!(core::mem::offset_of!(ExportedFdHandle, reserved) == 4);
    assert!(core::mem::offset_of!(ExportedFdHandle, rights) == 8);
    assert!(core::mem::offset_of!(ExportedFdHandle, metadata) == 16);
};

#[unsafe(no_mangle)]
pub extern "C" fn mochi_fd_export(
    fd: c_int,
    requested_rights: u64,
    output: *mut ExportedFdHandle,
) -> c_int {
    result_with_errno(export(fd, requested_rights, output), -1)
}

fn export(fd: c_int, rights: u64, output: *mut ExportedFdHandle) -> Result<c_int, c_int> {
    if output.is_null() {
        return Err(EFAULT);
    }
    if rights & !syscall::HANDLE_RIGHT_ALL != 0 {
        return Err(EINVAL);
    }
    io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            if !entry.handle.close_owned {
                return Err(mochios_posix_client::newlib_errno::EOPNOTSUPP);
            }
            let kind = inherited_fd_kind(entry.handle.kind).ok_or(EBADF)?;
            if posix_protocol::inherited_fd_kind_requires_handle(kind) != Some(true) {
                return Err(mochios_posix_client::newlib_errno::EOPNOTSUPP);
            }
            if entry.rights & syscall::HANDLE_RIGHT_DUPLICATE == 0 || rights & !entry.rights != 0 {
                return Err(EACCES);
            }
            let original = entry.handle.open_flags as u32;
            let read = rights & syscall::HANDLE_RIGHT_READ != 0;
            let write = rights & syscall::HANDLE_RIGHT_WRITE != 0;
            if read && !mochios_posix_client::fd::access_allows_read(original)
                || write && !mochios_posix_client::fd::access_allows_write(original)
            {
                return Err(EACCES);
            }
            let access = match (read, write) {
                (true, false) => 0,
                (false, true) => 1,
                (true, true) => 2,
                (false, false) => return Err(EINVAL),
            };
            let metadata =
                posix_protocol::encode_inherited_fd_metadata(posix_protocol::InheritedFdMetadata {
                    kind,
                    open_flags: (original & !3) | access,
                    descriptor_flags: u8::try_from(entry.descriptor_flags).map_err(|_| EIO)?,
                })
                .ok_or(EIO)?;
            io_resources::with(
                || {
                    let raw = syscall_errno(syscall::raw_syscall2(
                        syscall::SyscallNumber::HandleDuplicate,
                        entry.handle.lower_handle,
                        rights,
                    ))?;
                    let handle = u32::try_from(raw)
                        .ok()
                        .filter(|handle| {
                            *handle != 0 && u64::from(*handle) != entry.handle.lower_handle
                        })
                        .ok_or(EIO)?;
                    Ok(PendingHandles {
                        handles: [ObjectHandleAttachment { handle, rights }],
                        installed: false,
                    })
                },
                |owner| {
                    let mut bytes = [0; core::mem::size_of::<ExportedFdHandle>()];
                    bytes[..4].copy_from_slice(&owner.handles[0].handle.to_ne_bytes());
                    bytes[8..16].copy_from_slice(&rights.to_ne_bytes());
                    bytes[16..24].copy_from_slice(&metadata.to_ne_bytes());
                    // Copyout may fail, but may not deliver a C callback between
                    // exposing the reference and handing ownership to the caller.
                    let _delivery = defer_native_delivery();
                    user_copy::write(output.cast(), &bytes)?;
                    owner.installed = true;
                    Ok(0)
                },
            )
        },
    )
}
