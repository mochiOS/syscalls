//! C message adapters. Ancillary authority stays in explicit IPC attachments;
//! descriptor numbers and C pointers never leave this process.
use super::*;
use mochios_posix_client::{fd::FdReservations, socket_control as control, socket_transfer};
use mochios_posix_protocol::socket_transfer as wire;
#[path = "socket_message_memory.rs"]
mod memory;

const MSG_CTRUNC: c_int = 0x8;
const MSG_TRUNC: c_int = 0x20;
const MSG_PEEK: c_int = 0x2;
const MSG_WAITALL: c_int = 0x100;
const MSG_CMSG_CLOEXEC: c_int = 0x4000_0000;

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Message {
    name: *mut c_void,
    name_length: u32,
    vectors: *const IoVecMut,
    vector_count: usize,
    control: *mut c_void,
    control_length: usize,
    flags: c_int,
}

#[derive(Clone, Copy)]
struct Vector {
    base: *mut u8,
    length: usize,
}

struct OwnedHandle(u32);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        close_object_handle(self.0);
    }
}

struct Outgoing {
    entry: fd_lease::Lease,
    control: Option<VectorBuffer>,
    payload: Option<VectorBuffer>,
    ram: Option<OwnedHandle>,
    route: Option<(ObjectHandleAttachment<u32>, OwnedHandle)>,
    job: Option<(ObjectHandleAttachment<u32>, OwnedHandle)>,
    notification: Option<OwnedHandle>,
}

struct Incoming {
    reservation: FdReservations,
    entries: [Option<FdEntry>; control::MAX_RIGHTS],
    count: usize,
}

struct Receiving {
    entry: fd_lease::Lease,
    ram: Option<OwnedHandle>,
    incoming: Option<Incoming>,
    receipt: Option<OwnedHandle>,
}

struct ReceiveCall<'a> {
    entry: FdEntry,
    thread: &'a ThreadControl,
    caught: u64,
    wait: socket::SocketWait,
}
impl Drop for Incoming {
    fn drop(&mut self) {
        state().fds.cancel_group(&self.reservation);
        for entry in self.entries.iter().flatten() {
            close_object_handle(entry.handle.lower_handle as u32);
        }
    }
}

unsafe fn send_message(fd: c_int, input: *const Message, flags: c_int) -> Result<isize, c_int> {
    if input.is_null() {
        return Err(EFAULT);
    }
    let message = memory::read_message(input)?;
    if message.vector_count > mochios_posix_client::io_vector::IOV_MAX {
        return Err(EINVAL);
    }
    if (message.vector_count != 0 && message.vectors.is_null())
        || (message.control_length != 0 && message.control.is_null())
    {
        return Err(EFAULT);
    }
    mochios_posix_client::socket::message_options(flags & !socket::MSG_EOR, true)
        .map_err(|_| mochios_posix_client::newlib_errno::EOPNOTSUPP)?;
    let mut vectors = [Vector {
        base: ptr::null_mut(),
        length: 0,
    }; 1024];
    for (index, vector) in vectors[..message.vector_count].iter_mut().enumerate() {
        *vector = memory::read_vector(message.vectors, index)?;
        if (vector.base as usize).checked_add(vector.length).is_none() {
            return Err(EFAULT);
        }
    }
    let vectors = &vectors[..message.vector_count];
    let total = mochios_posix_client::io_vector::validate(message.vector_count as i32, |index| {
        (vectors[index].base.is_null(), vectors[index].length)
    })
    .map_err(vector_errno)?;
    io_resources::with(
        || {
            Ok(Outgoing {
                entry: with_fd_entry(fd)?,
                control: None,
                payload: None,
                ram: None,
                route: None,
                job: None,
                notification: None,
            })
        },
        |outgoing| unsafe { send_vectors(fd, message, flags, vectors, total, outgoing) },
    )
}

unsafe fn send_vectors(
    fd: c_int,
    message: Message,
    flags: c_int,
    vectors: &[Vector],
    total: usize,
    outgoing: &mut Outgoing,
) -> Result<isize, c_int> {
    let Outgoing {
        entry,
        control: control_storage,
        payload: storage,
        ram,
        route,
        job: outgoing_job,
        notification: outgoing_notification,
    } = outgoing;
    let flags = socket::message_flags(**entry, flags, true);
    let options = mochios_posix_client::socket::message_options(flags, true)
        .map_err(|_| mochios_posix_client::newlib_errno::EOPNOTSUPP)?;
    if !entry.handle.kind.is_socket() {
        return Err(mochios_posix_client::newlib_errno::from_status(-88));
    }
    if socket::is_record(**entry) && total > posix_protocol::socket_record::MAX_RECORD_SIZE {
        return Err(mochios_posix_client::newlib_errno::from_status(-90));
    }
    // Snapshot the complete control chain before lookup or staging. The codec
    // rejects malformed late headers without exposing an accepted prefix.
    if message.control_length > mochios_posix_client::io_vector::MAX_TRANSFER_BYTES {
        return Err(mochios_posix_client::newlib_errno::from_status(-105));
    }
    {
        let _native = defer_native_delivery();
        *control_storage = Some(VectorBuffer::new(message.control_length)?);
    }
    let ancillary = control_storage.as_mut().unwrap().bytes();
    if !ancillary.is_empty() {
        user_copy::read(message.control.cast(), ancillary)?;
    }
    let mut descriptors = [0; control::MAX_RIGHTS];
    let count =
        control::decode_rights(ancillary, &mut descriptors).map_err(|error| match error {
            control::Error::InvalidDescriptor => EBADF,
            control::Error::UnsupportedControl => mochios_posix_client::newlib_errno::EOPNOTSUPP,
            _ => EINVAL,
        })?;
    if count == 0 {
        {
            let _native = defer_native_delivery();
            *storage = Some(VectorBuffer::new(total)?);
        }
        let bytes = storage.as_mut().unwrap().bytes();
        let mut offset = 0;
        for vector in vectors {
            let size = vector.length.min(bytes.len() - offset);
            if size != 0 {
                user_copy::read(vector.base, &mut bytes[offset..offset + size])?;
                offset += size;
            }
            if offset == bytes.len() {
                break;
            }
        }
        if !message.name.is_null() && socket::is_datagram(**entry)? {
            if message.name_length as usize > mochios_posix_client::socket::MAX_SOCKADDR_LEN {
                return Err(EINVAL);
            }
            let mut address = [0; mochios_posix_client::socket::MAX_SOCKADDR_LEN];
            let address = &mut address[..message.name_length as usize];
            user_copy::read(message.name.cast(), address)?;
            let address = mochios_posix_client::socket::decode_sockaddr(address)
                .map_err(|status| mochios_posix_client::newlib_errno::from_status(status as i64))?;
            return socket_record::send_to(
                **entry,
                bytes.as_ptr() as u64,
                bytes.len(),
                flags,
                address,
            )
            .map(|record| record.count);
        }
        return socket::message_entry(**entry, bytes.as_ptr() as u64, bytes.len(), flags, true);
    }
    let record_oriented = socket::is_record(**entry);
    if total > wire::MAX_PAYLOAD_LEN as usize {
        return Err(mochios_posix_client::newlib_errno::from_status(-90));
    }
    let (raw, ram_rights) = {
        let _native = defer_native_delivery();
        let raw = syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryObjectCreate,
            ((total.max(1) + 4095) & !4095) as u64,
            0,
        ))?;
        *ram = Some(OwnedHandle(u32::try_from(raw).map_err(|_| EIO)?));
        let ram_rights = syscall_errno(syscall::raw_syscall1(
            syscall::SyscallNumber::HandleRightsGet,
            raw,
        ))?;
        (raw, ram_rights)
    };
    let mut offset = 0;
    for vector in vectors {
        if vector.length != 0 {
            let written = syscall_errno(syscall::raw_syscall4(
                syscall::SyscallNumber::HandleWriteAt,
                raw,
                vector.base as u64,
                vector.length as u64,
                offset as u64,
            ))?;
            if written != vector.length as u64 {
                return Err(EFAULT);
            }
            offset += vector.length;
        }
    }
    let transport = socket_record::endpoint()?;
    let (_, thread) = register_current_thread().ok_or(EAGAIN)?;
    let caught = thread.nonrestart_signal_generation.load(Ordering::Acquire);
    let mut wait = socket::SocketWait::new(**entry, syscall::HANDLE_SIGNAL_WRITABLE)?;
    let source = ObjectHandleAttachment {
        handle: entry.handle.lower_handle as u32,
        rights: entry.rights,
    };
    let mut address = [0; mochios_posix_client::socket::MAX_SOCKADDR_LEN];
    {
        let _native = defer_native_delivery();
        *route = if message.name.is_null() || !socket::is_datagram(**entry)? {
            None
        } else {
            let length = message.name_length as usize;
            if length > address.len() {
                return Err(EINVAL);
            }
            user_copy::read(message.name.cast(), &mut address[..length])?;
            let address = mochios_posix_client::socket::decode_sockaddr(&address[..length])
                .map_err(|status| mochios_posix_client::newlib_errno::from_status(status as i64))?;
            let route = mochios_posix_client::socket_record::prepare_route(
                &transport,
                source,
                total,
                address,
                close_object_handle,
            )
            .map_err(map_posix_client_error)?;
            Some((route, OwnedHandle(route.handle)))
        };
    }
    let job_handle = {
        let _native = defer_native_delivery();
        // Keep all source FDs stable across validation and every staging batch.
        // Only bounded worker calls happen here, never capacity waits. Once
        // appended, independent server-owned references survive sender close.
        let state = state();
        if state.fds.get(fd) != Some(**entry) {
            return Err(EBADF);
        }
        for &descriptor in &descriptors[..count] {
            let file = state.fds.get(descriptor).ok_or(EBADF)?;
            if inherited_fd_kind(file.handle.kind)
                .and_then(posix_protocol::inherited_fd_kind_requires_handle)
                != Some(true)
            {
                return Err(mochios_posix_client::newlib_errno::EOPNOTSUPP);
            }
            if file.rights & syscall::HANDLE_RIGHT_TRANSFER == 0 {
                return Err(EACCES);
            }
        }
        let job = socket_transfer::begin(
            &transport,
            route.as_ref().map(|(route, _)| *route).unwrap_or(source),
            total as u32,
            count as u16,
            close_object_handle,
        )
        .map_err(map_posix_client_error)?;
        let pending = OwnedHandle(job.handle);
        for (batch, descriptors) in descriptors[..count].chunks(wire::BATCH_SIZE).enumerate() {
            let files = core::array::from_fn::<_, { wire::BATCH_SIZE }, _>(|index| {
                let file = state
                    .fds
                    .get(descriptors[index.min(descriptors.len() - 1)])
                    .unwrap();
                socket_transfer::SendFile {
                    object: ObjectHandleAttachment {
                        handle: file.handle.lower_handle as u32,
                        rights: file.rights,
                    },
                    metadata: posix_protocol::InheritedFdMetadata {
                        kind: inherited_fd_kind(file.handle.kind).unwrap(),
                        open_flags: file.handle.open_flags as u32,
                        descriptor_flags: 0,
                    },
                }
            });
            socket_transfer::append(
                &transport,
                job,
                (batch * wire::BATCH_SIZE) as u16,
                &files[..descriptors.len()],
                close_object_handle,
            )
            .map_err(map_posix_client_error)?;
        }
        *outgoing_job = Some((job, pending));
        job
    };
    loop {
        if io_cancellation_requested(thread)
            || thread.nonrestart_signal_generation.load(Ordering::Acquire) != caught
        {
            return Err(EINTR);
        }
        let result = {
            let _native = defer_native_delivery();
            if record_oriented {
                socket_transfer::commit(
                    &transport,
                    job_handle,
                    ObjectHandleAttachment {
                        handle: raw as u32,
                        rights: ram_rights,
                    },
                    0,
                    total as u32,
                    close_object_handle,
                )
                .map(|_| total as u32)
            } else {
                socket_transfer::commit_prefix(
                    &transport,
                    job_handle,
                    ObjectHandleAttachment {
                        handle: raw as u32,
                        rights: ram_rights,
                    },
                    0,
                    total as u32,
                    close_object_handle,
                )
            }
        };
        match result {
            Ok(count) => return Ok(count as isize),
            Err(PosixClientError::Remote(-11))
                if !options.dont_wait && !handle_is_nonblocking(**entry)? =>
            {
                if let Some((route, _)) = route.as_ref() {
                    let notice =
                        object_entry(route.handle as u64, route.rights, FdKind::ObjectSocket, 2);
                    wait_for_handle_capacity(
                        notice,
                        syscall::HANDLE_SIGNAL_WRITABLE,
                        thread,
                        caught,
                        0,
                        wait.deadline(**entry)?,
                    )?;
                    continue;
                }
                let notification = {
                    let _native = defer_native_delivery();
                    let notification = mochios_posix_client::socket_record::wait_send(
                        &transport,
                        source,
                        if record_oriented { total } else { 1 },
                        close_object_handle,
                    )
                    .map_err(map_posix_client_error)?;
                    *outgoing_notification = Some(OwnedHandle(notification.handle));
                    notification
                };
                let notice = object_entry(
                    notification.handle as u64,
                    notification.rights,
                    FdKind::ObjectSocket,
                    2,
                );
                wait_for_handle_capacity(
                    notice,
                    syscall::HANDLE_SIGNAL_READABLE,
                    thread,
                    caught,
                    0,
                    wait.deadline(**entry)?,
                )?;
                let _native = defer_native_delivery();
                drop(outgoing_notification.take());
            }
            Err(error) => {
                let error = map_posix_client_error(error);
                if (!record_oriented || entry.handle.kind == FdKind::ObjectSeqPacket)
                    && !options.no_signal
                    && error == EPIPE
                {
                    generate_thread_signal(posix_protocol::SIGNAL_PIPE)?;
                }
                return Err(error);
            }
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sendmsg(fd: c_int, message: *const Message, flags: c_int) -> isize {
    pthread_testcancel();
    let result = result_with_errno(unsafe { send_message(fd, message, flags) }, -1);
    // Even zero bytes can commit rights. Do not cancel after publication.
    if result < 0 {
        pthread_testcancel();
    }
    result
}
unsafe fn scatter(vectors: &[Vector], ram: u32, copied: usize) -> Result<(), c_int> {
    let mut offset = 0;
    for vector in vectors {
        let length = vector.length.min(copied - offset);
        if length != 0 {
            let count = syscall_errno(syscall::raw_syscall4(
                syscall::SyscallNumber::HandleReadAt,
                ram as u64,
                vector.base as u64,
                length as u64,
                offset as u64,
            ))?;
            if count != length as u64 {
                return Err(EFAULT);
            }
            offset += length;
        }
        if offset == copied {
            break;
        }
    }
    Ok(())
}

unsafe fn receive(fd: c_int, output: *mut Message, flags: c_int) -> Result<isize, c_int> {
    if output.is_null() {
        return Err(EFAULT);
    }
    // As for readv, C metadata must be readable. Snapshot it once so concurrent
    // caller edits cannot change lengths after validation or record consumption.
    let message = memory::read_message(output)?;
    if message.vector_count > mochios_posix_client::io_vector::IOV_MAX {
        return Err(EINVAL);
    }
    if (message.vector_count != 0 && message.vectors.is_null())
        || (message.control_length != 0 && message.control.is_null())
    {
        return Err(EFAULT);
    }
    let mut vectors = [Vector {
        base: ptr::null_mut(),
        length: 0,
    }; 1024];
    for (index, vector) in vectors[..message.vector_count].iter_mut().enumerate() {
        *vector = memory::read_vector(message.vectors, index)?;
        if (vector.base as usize).checked_add(vector.length).is_none() {
            return Err(EFAULT);
        }
    }
    let vectors = &mut vectors[..message.vector_count];
    let total = mochios_posix_client::io_vector::validate(message.vector_count as i32, |index| {
        (vectors[index].base.is_null(), vectors[index].length)
    })
    .map_err(vector_errno)?;
    io_resources::with(
        || {
            Ok(Receiving {
                entry: with_fd_entry(fd)?,
                ram: None,
                incoming: None,
                receipt: None,
            })
        },
        |receiving| unsafe { receive_vectors(message, output, flags, vectors, total, receiving) },
    )
}

unsafe fn receive_vectors(
    mut message: Message,
    output: *mut Message,
    flags: c_int,
    vectors: &mut [Vector],
    total: usize,
    receiving: &mut Receiving,
) -> Result<isize, c_int> {
    let entry = *receiving.entry;
    if !entry.handle.kind.is_socket() {
        return Err(mochios_posix_client::newlib_errno::from_status(-88));
    }
    let wait_all = !socket::is_record(entry) && flags & MSG_WAITALL != 0 && flags & MSG_PEEK == 0;
    let (_, thread) = register_current_thread().ok_or(EAGAIN)?;
    let mut call = ReceiveCall {
        entry,
        thread,
        caught: thread.nonrestart_signal_generation.load(Ordering::Acquire),
        wait: socket::SocketWait::new(entry, syscall::HANDLE_SIGNAL_READABLE)?,
    };
    let original = message;
    let mut copied = 0;
    let mut head = 0;
    loop {
        let mut part = original;
        let result = unsafe {
            receive_once(
                &mut call,
                &mut part,
                &vectors[head..],
                total - copied,
                if wait_all {
                    flags & !MSG_WAITALL
                } else {
                    flags
                },
                receiving,
            )
        };
        let count = match result {
            Ok(count) => count as usize,
            Err(error) => {
                // A failed later WAITALL part must not publish its received
                // FDs when returning an earlier successful byte prefix.
                let _native = defer_native_delivery();
                drop(receiving.receipt.take());
                drop(receiving.incoming.take());
                if copied == 0 {
                    return Err(error);
                }
                break;
            }
        };
        copied += count;
        message = part;
        // Ancillary data forms a stream barrier even when control capacity is
        // zero (MSG_CTRUNC). Never consume a second rights-bearing segment.
        if !wait_all
            || count == 0
            || copied == total
            || message.control_length != 0
            || message.flags & MSG_CTRUNC != 0
        {
            break;
        }
        let mut left = count;
        while left != 0 {
            let vector = &mut vectors[head];
            if vector.length <= left {
                left -= vector.length;
                head += 1;
            } else {
                vector.base = vector.base.wrapping_add(left);
                vector.length -= left;
                left = 0;
            }
        }
    }
    let _native = defer_native_delivery();
    // Keep all received references rollback-owned until the final C header
    // copy succeeds, including when called inside an active native upcall.
    memory::write_message(output, message)?;
    if let Some(incoming) = receiving.incoming.as_mut() {
        let entries = core::array::from_fn::<_, { control::MAX_RIGHTS }, _>(|index| {
            incoming.entries[index].unwrap_or(entry)
        });
        let mut descriptors = [0; control::MAX_RIGHTS];
        state()
            .fds
            .commit_group(
                &incoming.reservation,
                &entries[..incoming.count],
                &mut descriptors,
            )
            .map_err(|_| EIO)?;
        incoming.entries.fill(None);
    }
    Ok(copied as isize)
}

unsafe fn receive_once(
    call: &mut ReceiveCall<'_>,
    output: &mut Message,
    vectors: &[Vector],
    total: usize,
    flags: c_int,
    receiving: &mut Receiving,
) -> Result<isize, c_int> {
    let entry = call.entry;
    let mut message = *output;
    let options = mochios_posix_client::socket::message_options(
        flags & !(MSG_TRUNC | MSG_CMSG_CLOEXEC),
        false,
    )
    .map_err(|_| mochios_posix_client::newlib_errno::EOPNOTSUPP)?;
    let record_oriented = socket::is_record(entry);
    // Like Linux UNIX streams, a peek returns the currently visible prefix
    // even with WAITALL. Only an empty queue waits; repeated offset reads would
    // combine different queue heads and bypass the first ancillary barrier.
    if !record_oriented && flags & MSG_TRUNC != 0 {
        return Err(mochios_posix_client::newlib_errno::EOPNOTSUPP);
    }
    let capacity = message.control_length.saturating_sub(control::HEADER_LEN) / 4;
    let maximum = capacity.min(control::MAX_RIGHTS);
    let length = total.min(posix_protocol::socket_record::MAX_RECORD_SIZE);
    let (raw, ram_rights) = {
        let _native = defer_native_delivery();
        drop(receiving.receipt.take());
        drop(receiving.incoming.take());
        drop(receiving.ram.take());
        let raw = syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryObjectCreate,
            ((length.max(1) + 4095) & !4095) as u64,
            0,
        ))?;
        receiving.ram = Some(OwnedHandle(u32::try_from(raw).map_err(|_| EIO)?));
        let ram_rights = syscall_errno(syscall::raw_syscall1(
            syscall::SyscallNumber::HandleRightsGet,
            raw,
        ))?;
        (raw, ram_rights)
    };
    let transport = socket_record::endpoint()?;
    let thread = call.thread;
    let caught = call.caught;
    let mut response = [0; wire::MAX_RECEIVE_REPLY_LEN];
    let received = loop {
        if io_cancellation_requested(thread)
            || thread.nonrestart_signal_generation.load(Ordering::Acquire) != caught
        {
            return Err(EINTR);
        }
        let result = {
            let _native = defer_native_delivery();
            let limit = if maximum == 0 { 0 } else { process_fd_limit()? };
            receiving.incoming = Some(Incoming {
                reservation: state()
                    .fds
                    .reserve_up_to(0, limit, maximum)
                    .map_err(|_| EMFILE)?,
                entries: [None; control::MAX_RIGHTS],
                count: 0,
            });
            let incoming = receiving.incoming.as_ref().unwrap();
            let source = ObjectHandleAttachment {
                handle: entry.handle.lower_handle as u32,
                rights: entry.rights,
            };
            let buffer = ObjectHandleAttachment {
                handle: raw as u32,
                rights: ram_rights,
            };
            let result = if options.peek {
                socket_transfer::peek(
                    &transport,
                    source,
                    buffer,
                    0,
                    length as u32,
                    incoming.reservation.len() as u16,
                    &mut response,
                    close_object_handle,
                )
            } else {
                socket_transfer::receive(
                    &transport,
                    source,
                    buffer,
                    0,
                    length as u32,
                    incoming.reservation.len() as u16,
                    &mut response,
                    close_object_handle,
                )
            };
            if let Ok(received) = &result {
                receiving.receipt = received.receipt.map(|receipt| OwnedHandle(receipt.handle));
            } else {
                drop(receiving.incoming.take());
            }
            result
        };
        match result {
            Ok(received) => break received,
            Err(PosixClientError::Remote(-11))
                if !options.dont_wait && !handle_is_nonblocking(entry)? =>
            {
                // Do not monopolize the local FD table while waiting for data.
                wait_for_handle_capacity(
                    entry,
                    syscall::HANDLE_SIGNAL_READABLE,
                    thread,
                    caught,
                    0,
                    call.wait.deadline(entry)?,
                )?;
            }
            Err(error) => return Err(map_posix_client_error(error)),
        }
    };
    let incoming = receiving.incoming.as_mut().unwrap();
    if let Some(receipt) = received.receipt {
        while incoming.count < received.message.available_rights as usize {
            let _native = defer_native_delivery();
            let remaining = received.message.available_rights as usize - incoming.count;
            let batch = socket_transfer::deliver(
                &transport,
                receipt,
                incoming.count as u16,
                remaining.min(4) as u16,
                close_object_handle,
            )
            .map_err(map_posix_client_error)?;
            if batch
                .files
                .iter()
                .flatten()
                .any(|file| fd_kind_from_inherited(file.metadata.kind).is_none())
            {
                for file in batch.files.into_iter().flatten() {
                    close_object_handle(file.object.handle);
                }
                return Err(EIO);
            }
            // Every dispatch kind is now validated before ownership is moved.
            for file in batch.files.into_iter().flatten() {
                let kind = fd_kind_from_inherited(file.metadata.kind).unwrap();
                let mut entry = object_entry(
                    file.object.handle as u64,
                    file.object.rights,
                    kind,
                    file.metadata.open_flags as c_int,
                );
                entry.descriptor_flags = if flags & MSG_CMSG_CLOEXEC != 0 {
                    FD_CLOEXEC as u32
                } else {
                    0
                };
                incoming.entries[incoming.count] = Some(entry);
                incoming.count += 1;
            }
        }
    }
    unsafe { scatter(vectors, raw as u32, received.message.copied as usize) }?;
    let mut native = [0; mochios_posix_client::socket::MAX_SOCKADDR_LEN];
    let required =
        mochios_posix_client::socket::encode_sockaddr(received.message.source, &mut native)
            .map_err(|_| EIO)?;
    if !record_oriented {
        message.name_length = 0;
    } else if !message.name.is_null() {
        user_copy::write(
            message.name.cast(),
            &native[..(message.name_length as usize).min(required)],
        )?;
        message.name_length = required as u32;
    }
    let mut descriptors = [0; control::MAX_RIGHTS];
    for (index, descriptor) in descriptors[..incoming.count].iter_mut().enumerate() {
        *descriptor = incoming.reservation.descriptor(index).ok_or(EIO)?;
    }
    let mut ancillary = [0; control::HEADER_LEN + 4 * (control::MAX_RIGHTS + 1)];
    let bound = message.control_length.min(ancillary.len());
    let encoded = control::encode_rights(&descriptors[..incoming.count], &mut ancillary[..bound]);
    let encoded = encoded.map_err(|_| EIO)?;
    if encoded.length != 0 {
        user_copy::write(message.control.cast(), &ancillary[..encoded.length])?;
    }
    message.control_length = encoded.length;
    message.flags =
        if entry.handle.kind == FdKind::ObjectSeqPacket && received.message.end_of_record {
            socket::MSG_EOR
        } else {
            0
        } | if received.message.length > received.message.copied {
            MSG_TRUNC
        } else {
            0
        } | if received.message.total_rights as usize > incoming.count {
            MSG_CTRUNC
        } else {
            0
        };
    *output = message;
    Ok(if flags & MSG_TRUNC != 0 {
        received.message.length
    } else {
        received.message.copied
    } as isize)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn recvmsg(fd: c_int, message: *mut Message, flags: c_int) -> isize {
    pthread_testcancel();
    let result = unsafe { receive(fd, message, flags) };
    let result = result_with_errno(result, -1);
    // An empty datagram may still have committed received FDs. Like accept,
    // never hide committed ownership behind a late cancellation check.
    if result < 0 {
        pthread_testcancel();
    }
    result
}
