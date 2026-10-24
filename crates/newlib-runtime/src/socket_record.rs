//! Datagram and sequenced-packet data path. RAM is explicitly attached to the delegated worker;
//! retries never concatenate records or change shared descriptor flags.
use super::*;
use mochios_posix_protocol::socket_record as wire;

static ENDPOINT: RuntimeMutex<Option<u32>> = RuntimeMutex::new(None);

pub(super) fn freeze_for_clone() -> RuntimeMutexGuard<'static, Option<u32>> {
    // Do not initialize an unused endpoint just to fork. Holding the cache
    // across capture excludes a partially published handle and a lock owned
    // by a thread that will not exist in the child.
    ENDPOINT.lock()
}

pub(super) fn endpoint() -> Result<SyscallEndpointTransport, c_int> {
    // Cache ownership must be published and its mutex released before a C
    // handler can abandon this frame. This is acquisition, not a capacity wait.
    let _native = defer_native_delivery();
    let mut cached = ENDPOINT.lock();
    let handle = match *cached {
        Some(handle) => handle,
        None => {
            let handle = posix_client()
                .map_err(map_posix_client_error)?
                .socket_record_endpoint(close_object_handle)
                .map_err(map_posix_client_error)?
                .handle;
            *cached = Some(handle);
            handle
        }
    };
    // Fork transfers the process's complete transferable native handle table;
    // exec starts a fresh cache and reacquires through its inherited endpoint.
    Ok(SyscallEndpointTransport::new(handle))
}

struct Buffer(u32);
impl Drop for Buffer {
    fn drop(&mut self) {
        close_object_handle(self.0);
    }
}

#[derive(Clone, Copy)]
pub(super) struct ResultRecord {
    pub count: isize,
    pub source: [u8; posix_protocol::socket::MAX_ADDRESS_LEN],
    pub source_length: usize,
}

pub(super) fn io(
    entry: FdEntry,
    buffer: u64,
    length: usize,
    flags: c_int,
    sending: bool,
) -> Result<ResultRecord, c_int> {
    io_using(entry, buffer, length, flags, sending, None)
}

pub(super) fn send_to(
    entry: FdEntry,
    buffer: u64,
    length: usize,
    flags: c_int,
    address: posix_protocol::socket::Address<'_>,
) -> Result<ResultRecord, c_int> {
    mochios_posix_client::socket::message_options(flags, true)
        .map_err(|_| mochios_posix_client::newlib_errno::EOPNOTSUPP)?;
    if length > isize::MAX as usize {
        return Err(EINVAL);
    }
    if length > wire::MAX_RECORD_SIZE {
        return Err(mochios_posix_client::newlib_errno::from_status(-90));
    }
    if length != 0 && buffer == 0 {
        return Err(EFAULT);
    }
    let transport = endpoint()?;
    let source = ObjectHandleAttachment {
        handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
        rights: entry.rights,
    };
    io_resources::with(
        || {
            let route = mochios_posix_client::socket_record::prepare_route(
                &transport,
                source,
                length,
                address,
                close_object_handle,
            )
            .map_err(map_posix_client_error)?;
            Ok((route, socket::PendingSocketJob(route.handle)))
        },
        |(route, _)| io_using(entry, buffer, length, flags, true, Some(*route)),
    )
}

fn io_using(
    entry: FdEntry,
    buffer: u64,
    length: usize,
    flags: c_int,
    sending: bool,
    route: Option<ObjectHandleAttachment<u32>>,
) -> Result<ResultRecord, c_int> {
    const MSG_TRUNC: c_int = 0x20;
    let flags = socket::message_flags(entry, flags, sending);
    let truncate = !sending && flags & MSG_TRUNC != 0;
    let options = mochios_posix_client::socket::message_options(
        if truncate { flags & !MSG_TRUNC } else { flags },
        sending,
    )
    .map_err(|_| mochios_posix_client::newlib_errno::EOPNOTSUPP)?;
    if length > isize::MAX as usize {
        return Err(EINVAL);
    }
    if length != 0 && buffer == 0 {
        return Err(EFAULT);
    }
    if sending && length > wire::MAX_RECORD_SIZE {
        return Err(mochios_posix_client::newlib_errno::from_status(-90));
    }
    let length = length.min(wire::MAX_RECORD_SIZE);
    let (_, thread) = register_current_thread().ok_or(EAGAIN)?;
    let caught = thread.nonrestart_signal_generation.load(Ordering::Acquire);
    let transport = endpoint()?;
    let interests = if sending {
        syscall::HANDLE_SIGNAL_WRITABLE
    } else {
        syscall::HANDLE_SIGNAL_READABLE
    };
    let mut wait = socket::SocketWait::new(entry, interests)?;
    io_resources::with(
        || {
            let size = (length.max(1) + 4095) & !4095;
            let raw = syscall_errno(syscall::raw_syscall2(
                syscall::SyscallNumber::MemoryObjectCreate,
                size as u64,
                0,
            ))?;
            let ram = Buffer(u32::try_from(raw).map_err(|_| EIO)?);
            let rights = syscall_errno(syscall::raw_syscall1(
                syscall::SyscallNumber::HandleRightsGet,
                raw,
            ))?;
            Ok((ram, rights, None::<socket::PendingSocketJob>))
        },
        |(ram, rights, pending)| {
            let raw = u64::from(ram.0);
            if sending && length != 0 {
                let count = syscall_errno(syscall::raw_syscall4(
                    syscall::SyscallNumber::HandleWriteAt,
                    raw,
                    buffer,
                    length as u64,
                    0,
                ))?;
                if count != length as u64 {
                    return Err(EFAULT);
                }
            }
            let socket = ObjectHandleAttachment {
                handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                rights: entry.rights,
            };
            let request = wire::Request {
                operation: if route.is_some() {
                    wire::Operation::SendRoute
                } else if sending {
                    wire::Operation::Send
                } else {
                    wire::Operation::Receive
                },
                offset: 0,
                length: length as u32,
                peek: options.peek,
            };
            let mut response = [0; wire::MAX_REPLY_LEN];
            let received = loop {
                if io_cancellation_requested(thread)
                    || thread.nonrestart_signal_generation.load(Ordering::Acquire) != caught
                {
                    return Err(EINTR);
                }
                let exchanged = {
                    // Retire unexpected reply attachments before reopening delivery.
                    let _native = defer_native_delivery();
                    mochios_posix_client::socket_record::exchange(
                        &transport,
                        request,
                        route.unwrap_or(socket),
                        ObjectHandleAttachment {
                            handle: ram.0,
                            rights: *rights,
                        },
                        &mut response,
                        close_object_handle,
                    )
                    .map_err(map_posix_client_error)
                };
                match exchanged {
                    Ok(reply) => break reply,
                    Err(EAGAIN) if !options.dont_wait && !handle_is_nonblocking(entry)? => {
                        if let Some(route) = route {
                            let notification = object_entry(
                                u64::from(route.handle),
                                route.rights,
                                FdKind::ObjectSocket,
                                2,
                            );
                            wait_for_handle_capacity(
                                notification,
                                syscall::HANDLE_SIGNAL_WRITABLE,
                                thread,
                                caught,
                                0,
                                wait.deadline(entry)?,
                            )?;
                        } else if sending {
                            let job = {
                                let _native = defer_native_delivery();
                                let job = mochios_posix_client::socket_record::wait_send(
                                    &transport,
                                    socket,
                                    length,
                                    close_object_handle,
                                )
                                .map_err(map_posix_client_error)?;
                                *pending = Some(socket::PendingSocketJob(job.handle));
                                job
                            };
                            let notification = object_entry(
                                u64::from(job.handle),
                                job.rights,
                                FdKind::ObjectSocket,
                                2,
                            );
                            wait_for_handle_capacity(
                                notification,
                                syscall::HANDLE_SIGNAL_READABLE,
                                thread,
                                caught,
                                0,
                                wait.deadline(entry)?,
                            )?;
                            let _native = defer_native_delivery();
                            drop(pending.take());
                        } else {
                            wait_for_handle_capacity(
                                entry,
                                interests,
                                thread,
                                caught,
                                0,
                                wait.deadline(entry)?,
                            )?;
                        }
                    }
                    Err(error) => {
                        if sending
                            && entry.handle.kind == FdKind::ObjectSeqPacket
                            && !options.no_signal
                            && error == EPIPE
                        {
                            io_resources::with(
                                || Ok(()),
                                |_| generate_thread_signal(posix_protocol::SIGNAL_PIPE),
                            )?;
                        }
                        return Err(error);
                    }
                }
            };
            if !sending && received.copied != 0 {
                let count = syscall_errno(syscall::raw_syscall4(
                    syscall::SyscallNumber::HandleReadAt,
                    raw,
                    buffer,
                    u64::from(received.copied),
                    0,
                ))?;
                if count != u64::from(received.copied) {
                    return Err(EFAULT);
                }
            }
            let mut result = ResultRecord {
                count: if truncate {
                    received.length as isize
                } else {
                    received.copied as isize
                },
                source: [0; posix_protocol::socket::MAX_ADDRESS_LEN],
                source_length: 0,
            };
            if let Some(source) = received.source {
                result.source_length = source.encode(&mut result.source).map_err(|_| EIO)?;
            }
            Ok(result)
        },
    )
}
