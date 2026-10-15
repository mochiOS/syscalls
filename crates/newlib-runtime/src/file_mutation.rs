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
