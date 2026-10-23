//! Blocking fcntl owns only a tracked FD pin and copied request while waiting.
//! No descriptor mutation gate or native-reference retirement lock spans it.
use super::*;
use posix_protocol::record_lock::{Operation, Request};

struct Pending {
    file: fd_lease::Lease,
    request: Request,
}

pub(super) fn fcntl(fd: c_int, input: *mut record_lock::Flock) -> Result<c_int, c_int> {
    pthread_testcancel();
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let caught = control.nonrestart_signal_generation.load(Ordering::Acquire);
    // SAFETY: Pending contains only a lifetime pin and copied scalar values.
    // Native reply Handles are validated/disposed before reopening callbacks.
    let result = unsafe {
        io_resources::with_fork_opaque(
            || {
                let _gate = record_lock::gate();
                let file = with_fd_entry(fd)?;
                let request = record_lock::read_request(*file, F_SETLKW, input)?;
                record_lock::cancel_exec()?;
                Ok(Pending { file, request })
            },
            |_| true,
            |pending| {
                if matches!(pending.request.operation, Operation::Unlock) {
                    let _gate = record_lock::gate();
                    record_lock::apply(*pending.file, pending.request)?;
                    return Ok(0);
                }
                let client = posix_client().map_err(map_posix_client_error)?;
                loop {
                    if io_cancellation_requested(control)
                        || control.nonrestart_signal_generation.load(Ordering::Acquire) != caught
                        || !pending.file.is_current()
                    {
                        return Err(EINTR);
                    }
                    let reply = {
                        // The native call cannot deliver a handler while in
                        // kernel wait. Reopen only after checking/discarding
                        // its reply, so a handler's fork cannot relabel a pin.
                        let _delivery = defer_native_delivery();
                        if !pending.file.is_current() {
                            return Err(EINTR);
                        }
                        let epoch = client
                            .thread_signal_epoch()
                            .map_err(map_posix_client_error)?;
                        if io_cancellation_requested(control)
                            || control.nonrestart_signal_generation.load(Ordering::Acquire)
                                != caught
                        {
                            return Err(EINTR);
                        }
                        client.wait_record_lock_since(
                            ObjectHandleAttachment {
                                handle: u32::try_from(pending.file.handle.lower_handle)
                                    .map_err(|_| EBADF)?,
                                rights: pending.file.rights,
                            },
                            pending.request,
                            epoch,
                        )
                    };
                    if !pending.file.is_current() {
                        return Err(EINTR);
                    }
                    match reply {
                        Ok(()) => return Ok(0),
                        Err(PosixClientError::Remote(posix_protocol::STATUS_EINTR)) => {
                            drain_pending_signals()?;
                        }
                        Err(error) => return Err(map_posix_client_error(error)),
                    }
                }
            },
        )
    };
    // Cleanup before cancellation; preserve a completed acquisition if it won.
    if result.is_err() {
        pthread_testcancel();
    }
    result
}

/// Called only after pthread_cancel has released its TCB/reference lock.
/// A disappearing target cannot still be blocked in its previous lifetime.
pub(super) fn interrupt(thread: Pthread) -> Result<(), c_int> {
    // Bootstrap runtimes without a delegated POSIX endpoint cannot own a
    // service wait. Their local/native cancellation must remain usable.
    if !has_posix_environment()? {
        return Ok(());
    }
    let rights = posix_protocol::THREAD_WAIT_INTERRUPT_RIGHTS;
    let reference = match thread_reference::snapshot(thread, rights) {
        Ok(reference) => reference,
        Err(ESRCH) => return Ok(()),
        Err(error) => return Err(error),
    };
    match posix_client()
        .map_err(map_posix_client_error)?
        .interrupt_thread_waits(ObjectHandleAttachment {
            handle: reference.handle(),
            rights,
        }) {
        Ok(()) | Err(PosixClientError::Remote(posix_protocol::STATUS_ESRCH)) => Ok(()),
        Err(error) => Err(map_posix_client_error(error)),
    }
}
