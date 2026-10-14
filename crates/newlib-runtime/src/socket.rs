//! Local socket FDs own native Provider Handles. Pair installation is atomic;
//! descriptor flags stay local while status options are shared by the Provider.

use super::*;
use mochios_posix_protocol::socket as wire;

struct PendingPair([FdReservation; 2]);

pub(super) struct SocketWait {
    started: Option<(u64, u64)>,
    deadline: Option<u64>,
}
impl SocketWait {
    pub(super) fn new(entry: FdEntry, interests: u64) -> Result<Self, c_int> {
        Ok(Self {
            started: if entry.handle.kind == FdKind::ObjectSocket
                && interests & (syscall::HANDLE_SIGNAL_READABLE | syscall::HANDLE_SIGNAL_WRITABLE)
                    != 0
            {
                Some((
                    monotonic_nanoseconds()?,
                    if interests & syscall::HANDLE_SIGNAL_READABLE != 0 {
                        wire::CONTROL_GET_RECEIVE_TIMEOUT
                    } else {
                        wire::CONTROL_GET_SEND_TIMEOUT
                    },
                ))
            } else {
                None
            },
            deadline: None,
        })
    }
    pub(super) fn deadline(&mut self, entry: FdEntry) -> Result<u64, c_int> {
        let Some((started, tag)) = self.started else {
            return Ok(syscall::HANDLE_WAIT_INFINITE);
        };
        if let Some(deadline) = self.deadline {
            return Ok(deadline);
        }
        let mut bytes = [0; 8];
        control(entry, tag, &[], &mut bytes)?;
        let deadline =
            mochios_posix_client::socket::socket_deadline(started, u64::from_le_bytes(bytes));
        self.deadline = Some(deadline);
        Ok(deadline)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setsockopt(
    fd: c_int,
    level: c_int,
    option: c_int,
    value: *const c_void,
    length: u32,
) -> c_int {
    let result = (|| {
        let entry = with_fd_entry(fd)?;
        if entry.handle.kind != FdKind::ObjectSocket {
            return Err(mochios_posix_client::newlib_errno::from_status(-88));
        }
        if level == 1 && matches!(option, 20 | 21) {
            if length < core::mem::size_of::<Timeval>() as u32 {
                return Err(EINVAL);
            }
            if value.is_null() {
                return Err(EFAULT);
            }
            let timeout = unsafe { value.cast::<Timeval>().read_unaligned() };
            let duration = mochios_posix_client::socket::socket_timeout_nanoseconds(
                timeout.tv_sec,
                timeout.tv_usec,
            )
            .map_err(|_| EINVAL)?;
            control(
                entry,
                if option == 20 {
                    wire::CONTROL_SET_RECEIVE_TIMEOUT
                } else {
                    wire::CONTROL_SET_SEND_TIMEOUT
                },
                &duration.to_le_bytes(),
                &mut [],
            )?;
            return Ok(0);
        }
        if length < core::mem::size_of::<c_int>() as u32 {
            return Err(EINVAL);
        }
        if value.is_null() {
            return Err(EFAULT);
        }
        let mut native = [0; 4];
        unsafe {
            ptr::copy_nonoverlapping(value.cast::<u8>(), native.as_mut_ptr(), native.len());
        }
        let (tag, payload) = mochios_posix_client::socket::newlib_setsockopt(
            level,
            option,
            c_int::from_ne_bytes(native),
        )
        .map_err(|error| mochios_posix_client::newlib_errno::from_status(i64::from(error)))?;
        control(entry, tag, &payload, &mut [])?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getsockopt(
    fd: c_int,
    level: c_int,
    option: c_int,
    value: *mut c_void,
    length: *mut u32,
) -> c_int {
    let result = (|| {
        let entry = with_fd_entry(fd)?;
        if entry.handle.kind != FdKind::ObjectSocket {
            return Err(mochios_posix_client::newlib_errno::from_status(-88));
        }
        if level == 1 && matches!(option, 20 | 21) {
            if length.is_null() {
                return Err(EFAULT);
            }
            let capacity = unsafe { length.read_unaligned() };
            if capacity > i32::MAX as u32 {
                return Err(EINVAL);
            }
            let count = (capacity as usize).min(core::mem::size_of::<Timeval>());
            if count != 0 && value.is_null() {
                return Err(EFAULT);
            }
            let mut bytes = [0; 8];
            control(
                entry,
                if option == 20 {
                    wire::CONTROL_GET_RECEIVE_TIMEOUT
                } else {
                    wire::CONTROL_GET_SEND_TIMEOUT
                },
                &[],
                &mut bytes,
            )?;
            let duration = u64::from_le_bytes(bytes);
            if duration % 1000 != 0 {
                return Err(EIO);
            }
            let mut native = [0; 16];
            native[..8].copy_from_slice(&((duration / 1_000_000_000) as i64).to_ne_bytes());
            native[8..].copy_from_slice(&((duration % 1_000_000_000 / 1000) as i64).to_ne_bytes());
            unsafe {
                if count != 0 {
                    ptr::copy_nonoverlapping(native.as_ptr(), value.cast::<u8>(), count);
                }
                length.write_unaligned(count as u32);
            }
            return Ok(0);
        }
        let tag = mochios_posix_client::socket::newlib_getsockopt_tag(level, option)
            .map_err(|error| mochios_posix_client::newlib_errno::from_status(i64::from(error)))?;
        if length.is_null() {
            return Err(EFAULT);
        }
        let capacity = unsafe { length.read() };
        if capacity > i32::MAX as u32 {
            return Err(EINVAL);
        }
        let count = (capacity as usize).min(core::mem::size_of::<c_int>());
        if count != 0 && value.is_null() {
            return Err(EFAULT);
        }
        let mut response = [0; 4];
        control(entry, tag, &[], &mut response)?;
        let decoded = mochios_posix_client::socket::newlib_getsockopt_value(tag, &response)
            .map_err(|_| EIO)?;
        unsafe {
            if count != 0 {
                ptr::copy_nonoverlapping(decoded.to_ne_bytes().as_ptr(), value.cast::<u8>(), count);
            }
            length.write(count as u32);
        }
        Ok(0)
    })();
    result_with_errno(result, -1)
}

struct PendingSocketJob(u32);
impl Drop for PendingSocketJob {
    fn drop(&mut self) {
        close_object_handle(self.0);
    }
}

unsafe fn connect_io(fd: c_int, address: *const c_void, length: u32) -> Result<c_int, c_int> {
    let entry = with_fd_entry(fd)?;
    if entry.handle.kind != FdKind::ObjectSocket {
        return Err(mochios_posix_client::newlib_errno::from_status(-88));
    }
    if address.is_null() {
        return Err(EFAULT);
    }
    if length as usize > mochios_posix_client::socket::MAX_SOCKADDR_LEN {
        return Err(EINVAL);
    }
    let bytes = unsafe { core::slice::from_raw_parts(address.cast::<u8>(), length as usize) };
    let address = mochios_posix_client::socket::decode_sockaddr(bytes)
        .map_err(|error| mochios_posix_client::newlib_errno::from_status(i64::from(error)))?;
    let (_, thread) = register_current_thread().ok_or(EAGAIN)?;
    let caught = thread.nonrestart_signal_generation.load(Ordering::Acquire);
    let mut wait = SocketWait::new(entry, syscall::HANDLE_SIGNAL_WRITABLE)?;
    let result = posix_client()
        .map_err(map_posix_client_error)?
        .connect_socket(
            mochios_posix_client::ObjectHandleAttachment {
                handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                rights: entry.rights,
            },
            address,
            close_object_handle,
        )
        .map_err(map_posix_client_error)?;
    let mochios_posix_client::socket::ConnectStarted::Pending(job) = result else {
        return Ok(0);
    };
    let _pending = PendingSocketJob(job.handle);
    let notification = object_entry(u64::from(job.handle), job.rights, FdKind::ObjectSocket, 2);
    loop {
        match control(notification, wire::CONTROL_CONNECT_RESULT, &[], &mut []) {
            Ok(()) => return Ok(0), // Ownership/connection is already committed.
            Err(EAGAIN) => {
                match wait_for_handle_capacity(
                    notification,
                    syscall::HANDLE_SIGNAL_READABLE | syscall::HANDLE_SIGNAL_PEER_CLOSED,
                    thread,
                    caught,
                    0,
                    wait.deadline(entry)?,
                ) {
                    Ok(_) => (),
                    Err(EAGAIN) => {
                        // Resolve the race at the owner of the connection
                        // transaction before dropping its notification Handle.
                        control(notification, wire::CONTROL_CONNECT_EXPIRE, &[], &mut [])?;
                        return Ok(0);
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn connect(fd: c_int, address: *const c_void, length: u32) -> c_int {
    pthread_testcancel();
    let result = unsafe { connect_io(fd, address, length) };
    let value = result_with_errno(result, -1);
    if value < 0 {
        pthread_testcancel();
    }
    value
}

unsafe fn accept_io(
    fd: c_int,
    address: *mut c_void,
    length: *mut u32,
    flags: c_int,
) -> Result<c_int, c_int> {
    if flags
        & !(mochios_posix_client::socket::SOCK_NONBLOCK
            | mochios_posix_client::socket::SOCK_CLOEXEC)
        != 0
    {
        return Err(EINVAL);
    }
    let entry = with_fd_entry(fd)?;
    if entry.handle.kind != FdKind::ObjectSocket {
        return Err(mochios_posix_client::newlib_errno::from_status(-88));
    }
    if !address.is_null() && length.is_null() {
        return Err(EFAULT);
    }
    let capacity = if address.is_null() {
        0
    } else {
        (unsafe { length.read() }) as usize
    };
    let limit = process_fd_limit()?;
    let pending = PendingFdReservation(state().fds.reserve_from(0, limit).map_err(|_| EMFILE)?);
    let client = posix_client().map_err(map_posix_client_error)?;
    let accepted = stream_io(entry, syscall::HANDLE_SIGNAL_READABLE, || {
        client
            .accept_socket(
                mochios_posix_client::ObjectHandleAttachment {
                    handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                    rights: entry.rights,
                },
                wire::Accept {
                    options: if flags & mochios_posix_client::socket::SOCK_NONBLOCK != 0 {
                        wire::NONBLOCKING
                    } else {
                        0
                    },
                },
                close_object_handle,
            )
            .map_err(map_posix_client_error)
    })?;
    let prepared = (|| {
        if !address.is_null() {
            let peer = accepted.peer_address().map_err(|_| EIO)?;
            let mut native = [0; mochios_posix_client::socket::MAX_SOCKADDR_LEN];
            let required = mochios_posix_client::socket::encode_sockaddr(peer, &mut native)
                .map_err(|_| EIO)?;
            unsafe {
                ptr::copy_nonoverlapping(
                    native.as_ptr(),
                    address.cast::<u8>(),
                    capacity.min(required),
                );
                length.write(required as u32);
            }
        }
        let local_flags = 2 | if flags & mochios_posix_client::socket::SOCK_CLOEXEC != 0 {
            O_CLOEXEC
        } else {
            0
        };
        let entry = object_entry(
            u64::from(accepted.socket.handle),
            accepted.socket.rights,
            FdKind::ObjectSocket,
            local_flags,
        );
        state()
            .fds
            .commit_reservation(&pending.0, entry)
            .map_err(|_| EIO)
    })();
    if prepared.is_err() {
        close_object_handle(accepted.socket.handle);
    }
    prepared
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn accept(fd: c_int, address: *mut c_void, length: *mut u32) -> c_int {
    pthread_testcancel();
    finish_accept(unsafe { accept_io(fd, address, length, 0) })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn accept4(
    fd: c_int,
    address: *mut c_void,
    length: *mut u32,
    flags: c_int,
) -> c_int {
    pthread_testcancel();
    finish_accept(unsafe { accept_io(fd, address, length, flags) })
}

fn finish_accept(result: Result<c_int, c_int>) -> c_int {
    let value = result_with_errno(result, -1);
    // A successfully installed FD (including fd 0) is committed ownership.
    // On interruption, reservations/received handles were cleaned up first.
    if value < 0 {
        pthread_testcancel();
    }
    value
}

#[unsafe(no_mangle)]
pub extern "C" fn listen(fd: c_int, backlog: c_int) -> c_int {
    let result = (|| {
        let entry = with_fd_entry(fd)?;
        if entry.handle.kind != FdKind::ObjectSocket {
            return Err(mochios_posix_client::newlib_errno::from_status(-88));
        }
        control(
            entry,
            wire::CONTROL_LISTEN,
            &(backlog.max(0) as u32).to_le_bytes(),
            &mut [],
        )?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bind(fd: c_int, address: *const c_void, length: u32) -> c_int {
    let result = (|| {
        let entry = with_fd_entry(fd)?;
        if entry.handle.kind != FdKind::ObjectSocket {
            return Err(mochios_posix_client::newlib_errno::from_status(-88));
        }
        if address.is_null() {
            return Err(EFAULT);
        }
        if length as usize > mochios_posix_client::socket::MAX_SOCKADDR_LEN {
            return Err(EINVAL);
        }
        let bytes = unsafe { core::slice::from_raw_parts(address.cast::<u8>(), length as usize) };
        let decoded = mochios_posix_client::socket::decode_sockaddr(bytes)
            .map_err(|error| mochios_posix_client::newlib_errno::from_status(i64::from(error)))?;
        let mut encoded = [0; wire::MAX_ADDRESS_LEN];
        let count = decoded.encode(&mut encoded).map_err(|_| EINVAL)?;
        control(entry, wire::CONTROL_BIND, &encoded[..count], &mut [])?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int {
    let result = (|| {
        let (create, cloexec) = mochios_posix_client::socket::newlib_create(domain, kind, protocol)
            .map_err(|error| mochios_posix_client::newlib_errno::from_status(i64::from(error)))?;
        // Keep the C API disabled until its record-aware data path is wired;
        // ordinary native stream I/O must never split a datagram into chunks.
        if create.kind == wire::Kind::Datagram {
            return Err(mochios_posix_client::newlib_errno::EOPNOTSUPP);
        }
        let limit = process_fd_limit()?;
        let pending = PendingFdReservation(state().fds.reserve_from(0, limit).map_err(|_| EMFILE)?);
        let opened = posix_client()
            .map_err(map_posix_client_error)?
            .open_socket(create, close_object_handle)
            .map_err(map_posix_client_error)?;
        let flags = 2 | if cloexec { O_CLOEXEC } else { 0 };
        let entry = object_entry(
            u64::from(opened.handle),
            opened.rights,
            FdKind::ObjectSocket,
            flags,
        );
        let result = state().fds.commit_reservation(&pending.0, entry);
        match result {
            Ok(fd) => Ok(fd),
            Err(_) => {
                close_object_handle(opened.handle);
                Err(EIO)
            }
        }
    })();
    result_with_errno(result, -1)
}
impl Drop for PendingPair {
    fn drop(&mut self) {
        let mut state = state();
        for reservation in &self.0 {
            state.fds.cancel_reservation(reservation);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn socketpair(
    domain: c_int,
    kind: c_int,
    protocol: c_int,
    output: *mut c_int,
) -> c_int {
    let result = (|| {
        if output.is_null() {
            return Err(EFAULT);
        }
        let (create, cloexec) = mochios_posix_client::socket::newlib_create(domain, kind, protocol)
            .map_err(|error| mochios_posix_client::newlib_errno::from_status(i64::from(error)))?;
        if create.kind == wire::Kind::Datagram {
            return Err(mochios_posix_client::newlib_errno::EOPNOTSUPP);
        }
        let limit = process_fd_limit()?;
        let pending = PendingPair(
            state()
                .fds
                .reserve_pair_from(0, limit)
                .map_err(|_| EMFILE)?,
        );
        let opened = posix_client()
            .map_err(map_posix_client_error)?
            .socket_pair(create, close_object_handle)
            .map_err(map_posix_client_error)?;
        let flags = 2 | if cloexec { O_CLOEXEC } else { 0 };
        let entries = opened.map(|opened| {
            object_entry(
                u64::from(opened.handle),
                opened.rights,
                FdKind::ObjectSocket,
                flags,
            )
        });
        let installed = state()
            .fds
            .commit_pair([&pending.0[0], &pending.0[1]], entries);
        match installed {
            Ok(fds) => {
                unsafe {
                    output.write(fds[0]);
                    output.add(1).write(fds[1]);
                }
                Ok(0)
            }
            Err(_) => {
                for opened in opened {
                    close_object_handle(opened.handle);
                }
                Err(EIO)
            }
        }
    })();
    result_with_errno(result, -1)
}

fn control(entry: FdEntry, tag: u64, input: &[u8], output: &mut [u8]) -> Result<(), c_int> {
    let count = query_control(entry, tag, input, output)?;
    if count != output.len() {
        return Err(EIO);
    }
    Ok(())
}

fn query_control(
    entry: FdEntry,
    tag: u64,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, c_int> {
    let count = syscall_errno(syscall::raw_syscall6(
        syscall::SyscallNumber::HandleControl,
        entry.handle.lower_handle,
        tag,
        input.as_ptr() as u64,
        input.len() as u64,
        output.as_mut_ptr() as u64,
        output.len() as u64,
    ))?;
    if count as usize > output.len() {
        return Err(EIO);
    }
    Ok(count as usize)
}

unsafe fn socket_name(
    fd: c_int,
    address: *mut c_void,
    length: *mut u32,
    peer: bool,
) -> Result<c_int, c_int> {
    let entry = with_fd_entry(fd)?;
    if entry.handle.kind != FdKind::ObjectSocket {
        return Err(mochios_posix_client::newlib_errno::from_status(-88));
    }
    if address.is_null() || length.is_null() {
        return Err(EFAULT);
    }
    let capacity = unsafe { length.read() } as usize;
    let mut encoded = [0; wire::MAX_ADDRESS_LEN];
    let tag = if peer {
        wire::CONTROL_PEER_ADDRESS
    } else {
        wire::CONTROL_LOCAL_ADDRESS
    };
    let count = query_control(entry, tag, &[], &mut encoded)?;
    let decoded = wire::Address::decode(&encoded[..count]).map_err(|_| EIO)?;
    let mut native = [0; mochios_posix_client::socket::MAX_SOCKADDR_LEN];
    let required =
        mochios_posix_client::socket::encode_sockaddr(decoded, &mut native).map_err(|_| EIO)?;
    unsafe {
        ptr::copy_nonoverlapping(
            native.as_ptr(),
            address.cast::<u8>(),
            capacity.min(required),
        );
        length.write(required as u32);
    }
    Ok(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getsockname(fd: c_int, address: *mut c_void, length: *mut u32) -> c_int {
    result_with_errno(unsafe { socket_name(fd, address, length, false) }, -1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpeername(fd: c_int, address: *mut c_void, length: *mut u32) -> c_int {
    result_with_errno(unsafe { socket_name(fd, address, length, true) }, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn shutdown(fd: c_int, how: c_int) -> c_int {
    let result = (|| {
        let entry = with_fd_entry(fd)?;
        if entry.handle.kind != FdKind::ObjectSocket {
            return Err(mochios_posix_client::newlib_errno::from_status(-88));
        }
        if !(0..=2).contains(&how) {
            return Err(EINVAL);
        }
        control(
            entry,
            wire::CONTROL_SHUTDOWN,
            &(how as u32).to_le_bytes(),
            &mut [],
        )?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

pub(super) fn get_status_flags(entry: FdEntry) -> Result<c_int, c_int> {
    let mut bytes = [0; 4];
    control(entry, wire::CONTROL_GET_OPTIONS, &[], &mut bytes)?;
    let options = u32::from_le_bytes(bytes);
    if options & !wire::NONBLOCKING != 0 {
        return Err(EIO);
    }
    Ok(2 | if options & wire::NONBLOCKING != 0 {
        O_NONBLOCK
    } else {
        0
    })
}

pub(super) fn set_status_flags(entry: FdEntry, flags: c_int) -> Result<(), c_int> {
    if flags & !(3 | O_NONBLOCK) != 0 {
        return Err(EINVAL);
    }
    let options: u32 = if flags & O_NONBLOCK != 0 {
        wire::NONBLOCKING
    } else {
        0
    };
    control(
        entry,
        wire::CONTROL_SET_OPTIONS,
        &options.to_le_bytes(),
        &mut [],
    )
}

pub(super) fn poll_events(entry: FdEntry, events: i16) -> Result<i16, c_int> {
    let mut bytes = [0; 4];
    control(entry, wire::CONTROL_READINESS, &[], &mut bytes)?;
    let bits = mochios_posix_client::socket::decode_readiness(&bytes).map_err(|_| EIO)?;
    Ok(mochios_posix_client::socket::poll_events(bits, events))
}

pub(super) fn stat(entry: FdEntry) -> Result<NewlibStat, c_int> {
    let mut bytes = [0; posix_protocol::FILE_STATUS_LEN];
    control(entry, wire::CONTROL_STAT, &[], &mut bytes)?;
    let status = posix_protocol::decode_file_status(&bytes).map_err(|_| EIO)?;
    translate_posix_stat(&status)
}

fn peek_since_wait(
    entry: FdEntry,
    thread: &ThreadControl,
    caught: u64,
    wait: &mut SocketWait,
    dont_wait: bool,
    offset: usize,
    mut operation: impl FnMut() -> Result<usize, c_int>,
) -> Result<usize, c_int> {
    loop {
        if io_cancellation_requested(thread)
            || thread.nonrestart_signal_generation.load(Ordering::Acquire) != caught
        {
            return Err(EINTR);
        }
        match operation() {
            Err(EAGAIN) if !dont_wait && !handle_is_nonblocking(entry)? => {
                let job = posix_client()
                    .map_err(map_posix_client_error)?
                    .wait_socket_receive(
                        ObjectHandleAttachment {
                            handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                            rights: entry.rights,
                        },
                        (offset as u64).checked_add(1).ok_or(EINVAL)?,
                        close_object_handle,
                    )
                    .map_err(map_posix_client_error)?;
                let _pending = PendingSocketJob(job.handle);
                let notification =
                    object_entry(u64::from(job.handle), job.rights, FdKind::ObjectSocket, 2);
                // This Handle becomes ready on new bytes or a terminal result,
                // not merely because the already-inspected prefix still exists.
                wait_for_handle_capacity(
                    notification,
                    syscall::HANDLE_SIGNAL_READABLE,
                    thread,
                    caught,
                    0,
                    wait.deadline(entry)?,
                )?;
            }
            result => return result,
        }
    }
}

fn message_io(
    fd: c_int,
    buffer: u64,
    length: usize,
    flags: c_int,
    sending: bool,
) -> Result<isize, c_int> {
    let entry = with_fd_entry(fd)?;
    if entry.handle.kind != FdKind::ObjectSocket {
        return Err(mochios_posix_client::newlib_errno::from_status(-88));
    }
    let options = mochios_posix_client::socket::message_options(flags, sending)
        .map_err(|_| mochios_posix_client::newlib_errno::EOPNOTSUPP)?;
    if length > isize::MAX as usize {
        return Err(EINVAL);
    }
    if length != 0 && buffer == 0 {
        return Err(EFAULT);
    }
    if length == 0 {
        return Ok(0);
    }
    let (_, thread) = register_current_thread().ok_or(EAGAIN)?;
    let caught = thread.nonrestart_signal_generation.load(Ordering::Acquire);
    let operation = if sending {
        syscall::SyscallNumber::HandleWrite
    } else {
        syscall::SyscallNumber::HandleRead
    };
    let interests = if sending {
        syscall::HANDLE_SIGNAL_WRITABLE
    } else {
        syscall::HANDLE_SIGNAL_READABLE
    };
    let mut wait = SocketWait::new(entry, interests)?;
    let mut io = |offset: usize, remaining: usize| {
        let address = buffer.checked_add(offset as u64).ok_or(EFAULT)?;
        if options.peek {
            return peek_since_wait(
                entry,
                thread,
                caught,
                &mut wait,
                options.dont_wait,
                offset,
                || {
                    syscall_errno(syscall::raw_syscall4(
                        syscall::SyscallNumber::HandleReadAt,
                        entry.handle.lower_handle,
                        address,
                        remaining as u64,
                        offset as u64,
                    ))
                    .and_then(|count| usize::try_from(count).map_err(|_| EIO))
                },
            );
        }
        let result = stream_io_since_wait(
            entry,
            interests,
            thread,
            caught,
            0,
            options.dont_wait,
            &mut wait,
            || {
                syscall_errno(syscall::raw_syscall3(
                    operation,
                    entry.handle.lower_handle,
                    address,
                    remaining as u64,
                ))
                .and_then(|count| usize::try_from(count).map_err(|_| EIO))
            },
        );
        if sending && !options.no_signal && matches!(result, Err(EPIPE)) {
            generate_thread_signal(posix_protocol::SIGNAL_PIPE)?;
        }
        result
    };
    if sending {
        let count = io(0, length)?;
        if count > length {
            return Err(EIO);
        }
        Ok(count as isize)
    } else {
        mochios_posix_client::socket::receive(length, options.wait_all, io)
            .map(|count| count as isize)
            .map_err(|error| match error {
                mochios_posix_client::socket::ReceiveError::InvalidResult => EIO,
                mochios_posix_client::socket::ReceiveError::Io(error) => error,
            })
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn send(fd: c_int, buffer: *const c_void, length: usize, flags: c_int) -> isize {
    pthread_testcancel();
    finish_io_cancellation(result_with_errno(
        message_io(fd, buffer as u64, length, flags, true),
        -1,
    ))
}

#[unsafe(no_mangle)]
pub extern "C" fn recv(fd: c_int, buffer: *mut c_void, length: usize, flags: c_int) -> isize {
    pthread_testcancel();
    finish_io_cancellation(result_with_errno(
        message_io(fd, buffer as u64, length, flags, false),
        -1,
    ))
}

#[unsafe(no_mangle)]
pub extern "C" fn sendto(
    fd: c_int,
    buffer: *const c_void,
    length: usize,
    flags: c_int,
    _address: *const c_void,
    _address_length: u32,
) -> isize {
    // All currently supported sockets are connection-mode streams. POSIX
    // ignores the destination here: never resolve it or change the peer.
    // Connectionless support must select a record-aware send path instead.
    send(fd, buffer, length, flags)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn recvfrom(
    fd: c_int,
    buffer: *mut c_void,
    length: usize,
    flags: c_int,
    address: *mut c_void,
    address_length: *mut u32,
) -> isize {
    pthread_testcancel();
    if address.is_null() {
        // With no requested address, address_length is not accessed.
        return recv(fd, buffer, length, flags);
    }
    if address_length.is_null() {
        return result_with_errno(Err(EFAULT), -1);
    }
    let capacity = unsafe { address_length.read() } as usize;
    let mut peer = [0u8; mochios_posix_client::socket::MAX_SOCKADDR_LEN];
    let mut required = peer.len() as u32;
    // A stream's peer cannot change after connection. Snapshot it before
    // consuming bytes, but publish it only on success (including EOF).
    // Datagrams need the source returned atomically with the received record.
    if let Err(error) = unsafe { socket_name(fd, peer.as_mut_ptr().cast(), &mut required, true) } {
        return result_with_errno(Err(error), -1);
    }
    let count = recv(fd, buffer, length, flags);
    if count >= 0 {
        unsafe {
            ptr::copy_nonoverlapping(
                peer.as_ptr(),
                address.cast::<u8>(),
                capacity.min(required as usize),
            );
            address_length.write(required);
        }
    }
    count
}
