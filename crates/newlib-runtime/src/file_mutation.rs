//! libc metadata mutations: cancel the queued position before running C code.
use super::*;
use core::pin::Pin;
use mochios_posix_client::{file_admission::Error, upcall_guard::Guard};

struct Resources<'a, R> {
    // Release the source reference before reopening application callbacks.
    source: R,
    callbacks: Option<Guard<'a>>,
}

enum WaitError {
    Notification,
    Failed(c_int),
}

fn delivery(control: &ThreadControl) -> Guard<'_> {
    Guard::enter(&control.native_delivery_defer).unwrap_or_else(|| process_exit(EOVERFLOW))
}

fn callbacks(control: &ThreadControl) -> Guard<'_> {
    control
        .callback_resources
        .defer_callbacks()
        .unwrap_or_else(|| process_exit(EOVERFLOW))
}

/// Exactly one native sleep. Never dispatch C or spin with a live ticket.
fn wait(control: &ThreadControl, ticket: &ObjectHandleAttachment<u32>) -> Result<(), WaitError> {
    let generation = control.multiplex_generation.load(Ordering::Acquire);
    if control.callback_resources.notification_pending() || io_cancellation_requested(control) {
        return Err(WaitError::Notification);
    }
    let mut item = syscall::HandleWaitItem {
        handle: ticket.handle,
        interests: syscall::HANDLE_SIGNAL_READABLE | syscall::HANDLE_SIGNAL_PEER_CLOSED,
        ..Default::default()
    };
    let guard = syscall::HandleWaitGuard {
        address: (&control.multiplex_generation as *const AtomicU64) as u64,
        expected: generation,
    };
    let result = syscall_errno(syscall::raw_syscall4(
        syscall::SyscallNumber::HandleWaitManyGuarded,
        (&mut item as *mut syscall::HandleWaitItem) as u64,
        1,
        syscall::HANDLE_WAIT_INFINITE,
        (&guard as *const syscall::HandleWaitGuard) as u64,
    ));
    if control.callback_resources.notification_pending()
        || io_cancellation_requested(control)
        || control.multiplex_generation.load(Ordering::Acquire) != generation
    {
        return Err(WaitError::Notification);
    }
    match result {
        Err(EAGAIN) => Err(WaitError::Notification),
        Err(error) => Err(WaitError::Failed(error)),
        Ok(_) if item.observed & syscall::HANDLE_SIGNAL_READABLE != 0 => Ok(()),
        Ok(_) => Err(WaitError::Failed(EIO)),
    }
}

fn execute<'a, R, const SIZE: usize>(
    control: &'a ThreadControl,
    client: &PosixClient<SyscallEndpointTransport>,
    prepared: &mochios_posix_client::file_admission::Prepared<u32, SIZE>,
    mut scope: Pin<&mut callback_resources::Scope<'a, Resources<'a, R>>>,
) -> Result<Option<ObjectHandleAttachment<u32>>, c_int> {
    let caught = control.nonrestart_signal_generation.load(Ordering::Acquire);
    loop {
        match client.execute_file_mutation(prepared, |ticket| wait(control, ticket)) {
            Ok(value) => return Ok(value),
            Err(Error::Wait(WaitError::Notification)) => {
                // execute_file_mutation has already closed its ticket. Only
                // now may a handler reenter libc, pthread_exit or siglongjmp.
                {
                    let _delivery = delivery(control);
                    scope.as_mut().resource_mut().unwrap().callbacks.take();
                }
                drain_pending_signals()?;
                if io_cancellation_requested(control)
                    || control.nonrestart_signal_generation.load(Ordering::Acquire) != caught
                {
                    return Err(EINTR);
                }
                let _delivery = delivery(control);
                scope.as_mut().resource_mut().unwrap().callbacks = Some(callbacks(control));
                // Restart the captured input, not the caller's pathname/FD.
            }
            Err(Error::Wait(WaitError::Failed(error))) => return Err(error),
            Err(Error::Operation(PosixClientError::Remote(
                posix_protocol::STATUS_FILE_SIZE_LIMIT,
            ))) => {
                generate_thread_signal(posix_protocol::SIGNAL_XFSZ)?;
                return Err(EFBIG);
            }
            Err(Error::Operation(error)) => return Err(map_posix_client_error(error)),
        }
    }
}

pub(super) fn ftruncate(fd: c_int, length: u64) -> Result<c_int, c_int> {
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let native = delivery(control);
    // The lease cannot exist across an application callback until its pinned
    // owner is published. STATE is released before publication or any IPC.
    let resources = Resources {
        source: with_fd_entry(fd)?,
        callbacks: Some(callbacks(control)),
    };
    let mut scope = core::pin::pin!(callback_resources::Scope::new(
        &control.callback_resources,
        control.active_signal_scope_id.load(Ordering::Acquire),
        resources
    ));
    unsafe { scope.as_mut().activate() };
    drop(native);
    let result = (|| {
        let entry = *scope.as_ref().get_ref().resource().unwrap().source;
        if entry.handle.kind == FdKind::ObjectSharedMemory {
            shared_memory::truncate(entry, length)?;
            return Ok(0);
        }
        if entry.handle.kind == FdKind::ObjectTerminalFile {
            return Err(EINVAL);
        }
        if !matches!(
            entry.handle.kind,
            FdKind::ObjectFile | FdKind::ObjectSpecial
        ) {
            return Err(EBADF);
        }
        if !mochios_posix_client::fd::access_allows_write(entry.handle.open_flags as u32) {
            return Err(EINVAL);
        }
        let client = posix_client().map_err(map_posix_client_error)?;
        let prepared = client
            .prepare_ftruncate(
                ObjectHandleAttachment {
                    handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                    rights: entry.rights,
                },
                length,
            )
            .map_err(map_posix_client_error)?;
        execute(control, client, &prepared, scope.as_mut())?;
        Ok(0)
    })();
    {
        let _delivery = delivery(control);
        // Explicit retirement keeps the source destructor inside the native
        // delivery guard, including error paths and non-restarting signals.
        unsafe { scope.as_mut().retire() };
    }
    drain_pending_signals()?;
    result
}

pub(super) fn truncate(path: *const c_char, length: u64) -> Result<c_int, c_int> {
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let native = delivery(control);
    let client = posix_client().map_err(map_posix_client_error)?;
    let prepared = {
        // Capture before acquiring mutation resources or reopening callbacks;
        // never scan beyond the wire pathname bound looking for a NUL.
        let mut snapshot = [0u8; posix_protocol::MAX_PATH_LEN];
        let length_of_path = path_io::capture(path, &mut snapshot)?;
        let path = &snapshot[..length_of_path];
        client
            .prepare_truncate_at(StatAtBase::ProcessCwd, path, length)
            .map_err(map_posix_client_error)?
    };
    let mut scope = core::pin::pin!(callback_resources::Scope::new(
        &control.callback_resources,
        control.active_signal_scope_id.load(Ordering::Acquire),
        Resources {
            source: (),
            callbacks: Some(callbacks(control)),
        }
    ));
    unsafe { scope.as_mut().activate() };
    drop(native);
    let result = execute(control, client, &prepared, scope.as_mut()).map(|_| 0);
    {
        let _delivery = delivery(control);
        unsafe { scope.as_mut().retire() };
    }
    drain_pending_signals()?;
    result
}

struct OpenResources {
    reservation: PendingFdReservation,
    opened: Option<ObjectHandleAttachment<u32>>,
    _directory: Option<fd_lease::Lease>,
}

impl Drop for OpenResources {
    fn drop(&mut self) {
        if let Some(opened) = self.opened.take() {
            close_object_handle(opened.handle);
        }
        // The reservation's own destructor then cancels any uncommitted slot.
    }
}

pub(super) fn open(path: *const c_char, flags: c_int, mode: c_int) -> Result<c_int, c_int> {
    open_in_slot(-2, path, flags, mode, None, None)
}

/// Initialize an enclosing owner while the FD is still reserved. This is an
/// internal Rust handoff, never an application callback: it must not wait or
/// invoke C. Failure leaves the received Handle and reservation with this scope.
pub(super) fn open_with_handoff(
    path: *const c_char,
    flags: c_int,
    mode: c_int,
    handoff: &mut dyn FnMut(c_int) -> Result<(), c_int>,
) -> Result<c_int, c_int> {
    open_in_slot(-2, path, flags, mode, None, Some(handoff))
}

pub(super) fn open_at(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: c_int,
) -> Result<c_int, c_int> {
    open_in_slot(dirfd, path, flags, mode, None, None)
}

pub(super) fn open_for_spawn(
    path: *const c_char,
    flags: c_int,
    mode: c_int,
    fd: c_int,
) -> Result<c_int, c_int> {
    open_in_slot(-2, path, flags, mode, Some(fd), None)
}

fn open_in_slot(
    dirfd: c_int,
    path: *const c_char,
    flags: c_int,
    mode: c_int,
    target: Option<c_int>,
    mut handoff: Option<&mut dyn FnMut(c_int) -> Result<(), c_int>>,
) -> Result<c_int, c_int> {
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let native = delivery(control);
    if target.is_none() && io_cancellation_requested(control) {
        return Err(EINTR);
    }
    let client = posix_client().map_err(map_posix_client_error)?;
    let options = posix_open_options(flags)?;
    let (prepared, directory) = {
        let mut snapshot = [0u8; posix_protocol::MAX_PATH_LEN];
        let length = path_io::capture(path, &mut snapshot)?;
        let path = &snapshot[..length];
        let (base, directory) = rename_posix_base(dirfd, path)?;
        let base = match base {
            StatAtBase::ProcessRoot => OpenAtBase::ProcessRoot,
            StatAtBase::ProcessCwd => OpenAtBase::ProcessCwd,
            StatAtBase::Directory(handle) => OpenAtBase::Directory(handle),
        };
        let prepared = client
            .prepare_open_at(base, options, mode as u32, path)
            .map_err(map_posix_client_error)?;
        (prepared, directory)
    };
    let limit = process_fd_limit()?;
    let reservation = {
        let mut state = state();
        let (minimum, limit) = match target {
            Some(fd) => {
                if fd < 0 || fd >= limit {
                    return Err(EBADF);
                }
                // A spawn open action closes the target before opening, even
                // on failure. Reserve that exact slot, not a temporary FD.
                state.fds.close_for_spawn(fd, &mut RuntimeFdOps);
                (fd, fd + 1)
            }
            None => (0, limit),
        };
        PendingFdReservation(state.fds.reserve_from(minimum, limit).map_err(|_| EMFILE)?)
    };
    let mut scope = core::pin::pin!(callback_resources::Scope::new(
        &control.callback_resources,
        control.active_signal_scope_id.load(Ordering::Acquire),
        Resources {
            source: OpenResources {
                reservation,
                opened: None,
                _directory: directory
            },
            callbacks: Some(callbacks(control)),
        }
    ));
    unsafe { scope.as_mut().activate() };
    drop(native);
    let mut completion_delivery = None;
    let result = (|| {
        let opened = execute(control, client, &prepared, scope.as_mut())?.ok_or(EIO)?;
        // execute leaves callbacks deferred on success. Publish ownership
        // before fstat; no C handler can escape with an untracked reply Handle.
        scope.as_mut().resource_mut().unwrap().source.opened = Some(opened);
        let status = client.fstat(opened).map_err(map_posix_client_error)?;
        let kind = file_kind::opened(opened, status.mode)?;
        let entry = object_entry(u64::from(opened.handle), opened.rights, kind, flags);
        // Dispatch while the result is still owned by the tracked scope,
        // BEFORE publishing an FD that C has not yet received. A nonlocal
        // escape here releases both the Handle and the reserved slot.
        loop {
            {
                let _delivery = delivery(control);
                scope.as_mut().resource_mut().unwrap().callbacks.take();
            }
            drain_pending_signals()?;
            let native = delivery(control);
            if target.is_none() && io_cancellation_requested(control) {
                return Err(EINTR);
            }
            if control.callback_resources.notification_pending() {
                drop(native);
                continue;
            }
            completion_delivery = Some(native);
            break;
        }
        if let Some(handoff) = handoff.as_mut() {
            let fd = scope
                .as_ref()
                .get_ref()
                .resource()
                .unwrap()
                .source
                .reservation
                .0
                .descriptor();
            handoff(fd)?;
        }
        // Keep native delivery closed through installation AND retirement.
        // There must be no fallible C dispatch after ownership moves to the FD
        // table: an error then would hide a successfully installed descriptor.
        let installed = {
            let source = &scope.as_ref().get_ref().resource().unwrap().source;
            state().fds.commit_reservation(&source.reservation.0, entry)
        };
        let fd = installed.map_err(|_| EIO)?;
        // Ownership moved to the FD table. Disarm cleanup before C can run.
        scope.as_mut().resource_mut().unwrap().source.opened = None;
        Ok(fd)
    })();
    {
        let _delivery = delivery(control);
        unsafe { scope.as_mut().retire() };
    }
    drop(completion_delivery);
    if result.is_err() {
        drain_pending_signals()?;
    }
    result
}
