//! Local socket FDs own native Provider Handles. Pair installation is atomic;
//! descriptor flags stay local while status options are shared by the Provider.

use super::*;
use mochios_posix_protocol::socket as wire;

struct PendingPair([FdReservation; 2]);

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

struct PendingConnection(u32);
impl Drop for PendingConnection {
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
    let _pending = PendingConnection(job.handle);
    let notification = object_entry(u64::from(job.handle), job.rights, FdKind::ObjectSocket, 2);
    loop {
        match control(notification, wire::CONTROL_CONNECT_RESULT, &[], &mut []) {
            Ok(()) => return Ok(0), // Ownership/connection is already committed.
            Err(EAGAIN) => {
                wait_for_handle_since(
                    notification,
                    syscall::HANDLE_SIGNAL_READABLE | syscall::HANDLE_SIGNAL_PEER_CLOSED,
                    thread,
                    caught,
                )?;
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
    let bits = u32::from_le_bytes(bytes);
    if bits & !31 != 0 {
        return Err(EIO);
    }
    Ok(mochios_posix_client::socket::poll_events(bits, events))
}

pub(super) fn stat(entry: FdEntry) -> Result<NewlibStat, c_int> {
    let mut bytes = [0; posix_protocol::FILE_STATUS_LEN];
    control(entry, wire::CONTROL_STAT, &[], &mut bytes)?;
    let status = posix_protocol::decode_file_status(&bytes).map_err(|_| EIO)?;
    translate_posix_stat(&status)
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
        .map_err(|error| mochios_posix_client::newlib_errno::from_status(i64::from(error)))?;
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
    let io = |offset: usize, remaining: usize| {
        let address = buffer.checked_add(offset as u64).ok_or(EFAULT)?;
        let result = stream_io_since_mode(
            entry,
            interests,
            thread,
            caught,
            0,
            options.dont_wait,
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
