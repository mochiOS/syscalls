//! Bridge an explicitly owned native file reference into the local FD table.
//! The source is borrowed; only a new rights-preserving duplicate is consumed.
use super::*;
use fd_creation::PendingHandles;

#[unsafe(no_mangle)]
pub extern "C" fn mochi_fd_from_file_handle(source: u32, flags: c_int) -> c_int {
    result_with_errno(import(source, flags), -1)
}

fn import(source: u32, flags: c_int) -> Result<c_int, c_int> {
    if flags & !O_CLOEXEC != 0 {
        return Err(EINVAL);
    }
    if source == 0 {
        return Err(EBADF);
    }
    io_resources::with(
        || {
            let rights = syscall_errno(syscall::raw_syscall1(
                syscall::SyscallNumber::HandleRightsGet,
                u64::from(source),
            ))?;
            if rights & !syscall::HANDLE_RIGHT_ALL != 0 {
                return Err(EIO);
            }
            let required = syscall::HANDLE_RIGHT_DUPLICATE | syscall::HANDLE_RIGHT_TRANSFER;
            if rights & required != required
                || rights & (syscall::HANDLE_RIGHT_READ | syscall::HANDLE_RIGHT_WRITE) == 0
            {
                return Err(EACCES);
            }
            let limit = process_fd_limit()?;
            let reservation =
                PendingFdReservation(state().fds.reserve_from(0, limit).map_err(|_| EMFILE)?);
            let raw = syscall_errno(syscall::raw_syscall2(
                syscall::SyscallNumber::HandleDuplicate,
                u64::from(source),
                rights,
            ))?;
            let handle = u32::try_from(raw)
                .ok()
                .filter(|handle| *handle != 0 && *handle != source)
                .ok_or(EIO)?;
            Ok((
                reservation,
                PendingHandles {
                    handles: [ObjectHandleAttachment { handle, rights }],
                    installed: false,
                },
            ))
        },
        |(reservation, opened)| {
            let file = opened.handles[0];
            // This inspects only the explicitly attached reference, never a
            // pathname. A process/RAM/stream Handle cannot masquerade as a file.
            let status = posix_client()
                .map_err(map_posix_client_error)?
                .fstat(file)
                .map_err(map_posix_client_error)?;
            let kind = match status.mode & 0o170000 {
                0o100000 => FdKind::ObjectFile,
                0o040000 => FdKind::ObjectDirectory,
                _ => return Err(mochios_posix_client::newlib_errno::EOPNOTSUPP),
            };
            let access = match (
                file.rights & syscall::HANDLE_RIGHT_READ != 0,
                file.rights & syscall::HANDLE_RIGHT_WRITE != 0,
            ) {
                (true, false) => 0,
                (false, true) => 1,
                (true, true) => 2,
                (false, false) => return Err(EACCES),
            };
            let entry = object_entry(u64::from(file.handle), file.rights, kind, access | flags);
            // No C callback or fallible provider operation may follow ownership
            // publication. The tracked owner disarms before delivery reopens.
            let _delivery = defer_native_delivery();
            let fd = state()
                .fds
                .commit_reservation(&reservation.0, entry)
                .map_err(|_| EIO)?;
            opened.installed = true;
            Ok(fd)
        },
    )
}
