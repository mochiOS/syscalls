//! Configure an owned PTY pair before publishing either local descriptor.
use super::fd_creation::{PendingHandles, PendingPair};
use super::*;

pub(super) fn create(
    master: *mut c_int,
    slave: *mut c_int,
    name: *mut c_char,
    attributes: *const NewlibTermios,
    window: *const NewlibWinSize,
) -> Result<c_int, c_int> {
    io_resources::with_initialized(
        || {
            let limit = process_fd_limit()?;
            let pending = PendingPair(
                state()
                    .fds
                    .reserve_pair_from(0, limit)
                    .map_err(|_| EMFILE)?,
            );
            let pair = posix_client()
                .and_then(|client| client.open_pty())
                .map_err(map_posix_client_error)?;
            let opened = PendingHandles {
                handles: [pair.master, pair.slave],
                installed: false,
            };
            let required = syscall::HANDLE_RIGHT_READ
                | syscall::HANDLE_RIGHT_WRITE
                | syscall::HANDLE_RIGHT_WAIT
                | syscall::HANDLE_RIGHT_CONTROL
                | syscall::HANDLE_RIGHT_DUPLICATE
                | syscall::HANDLE_RIGHT_TRANSFER;
            if opened
                .handles
                .iter()
                .any(|handle| handle.rights & required != required)
            {
                return Err(EACCES);
            }
            Ok((
                pending,
                opened,
                None::<NewlibTermios>,
                None::<NewlibWinSize>,
            ))
        },
        |(_, _, captured_attributes, captured_window)| {
            // Both Handles and reserved slots remain rollback-owned while
            // faultable input is copied, including inside an active upcall.
            if !attributes.is_null() {
                *captured_attributes = Some(terminal_memory::read_attributes(attributes)?);
            }
            if !window.is_null() {
                *captured_window = Some(terminal_memory::read_window(window)?);
            }
            Ok(())
        },
        |(pending, opened, attributes, window)| {
            let entries = opened.handles.map(|handle| {
                object_entry(
                    u64::from(handle.handle),
                    handle.rights,
                    FdKind::ObjectPty,
                    2,
                )
            });
            if let Some(attributes) = attributes {
                set_terminal_attributes(entries[1], TCSANOW, *attributes)?;
            }
            if let Some(window) = window {
                set_terminal_window_size(entries[1], *window)?;
            }
            if !name.is_null() {
                // Legacy openpty has no buffer-size argument. Copy only the
                // validated, NUL-terminated name, not the maximum capacity.
                // Resources remain registered if copying faults/abandons C.
                terminal_name::copy(entries[0], name, posix_protocol::pty_name::MAX_LEN)?;
            }
            let _native = defer_native_delivery();
            // An earlier output may have been copied when a later one fails,
            // but neither descriptor is installed until both copies succeed.
            user_copy::write(master.cast(), &pending.0[0].descriptor().to_ne_bytes())?;
            user_copy::write(slave.cast(), &pending.0[1].descriptor().to_ne_bytes())?;
            state()
                .fds
                .commit_pair([&pending.0[0], &pending.0[1]], entries)
                .map_err(|_| EIO)?;
            opened.installed = true;
            Ok(0)
        },
    )
}
