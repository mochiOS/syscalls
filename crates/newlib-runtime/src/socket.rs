//! Local socket FDs own native Provider Handles. Pair installation is atomic;
//! descriptor flags stay local while status options are shared by the Provider.

use super::fd_creation::{PendingHandles, PendingPair};
use super::*;
use mochios_posix_protocol::socket as wire;

pub(super) struct SocketWait {
    started: Option<(u64, u64)>,
    deadline: Option<u64>,
}
impl SocketWait {
    pub(super) fn new(entry: FdEntry, interests: u64) -> Result<Self, c_int> {
        Ok(Self {
            started: if entry.handle.kind.is_socket()
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
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            if !entry.handle.kind.is_socket() {
                return Err(mochios_posix_client::newlib_errno::from_status(-88));
            }
            if level == 1 && matches!(option, 20 | 21) {
                if length < core::mem::size_of::<Timeval>() as u32 {
                    return Err(EINVAL);
                }
                if value.is_null() {
                    return Err(EFAULT);
                }
                let timeout = socket_memory::read_timeout(value)?;
                let duration = mochios_posix_client::socket::socket_timeout_nanoseconds(
                    timeout.tv_sec,
                    timeout.tv_usec,
                )
                .map_err(|_| EINVAL)?;
                control(
                    **entry,
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
            user_copy::read(value.cast(), &mut native)?;
            let (tag, payload) = mochios_posix_client::socket::newlib_setsockopt(
                level,
                option,
                c_int::from_ne_bytes(native),
            )
            .map_err(|error| mochios_posix_client::newlib_errno::from_status(i64::from(error)))?;
            control(**entry, tag, &payload, &mut [])?;
            Ok(0)
        },
    );
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
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            if !entry.handle.kind.is_socket() {
                return Err(mochios_posix_client::newlib_errno::from_status(-88));
            }
            if level == 1 && matches!(option, 20 | 21) {
                if length.is_null() {
                    return Err(EFAULT);
                }
                let capacity = socket_memory::read_length(length)?;
                if capacity > i32::MAX as u32 {
                    return Err(EINVAL);
                }
                let count = (capacity as usize).min(core::mem::size_of::<Timeval>());
                if count != 0 && value.is_null() {
                    return Err(EFAULT);
                }
                let mut bytes = [0; 8];
                control(
                    **entry,
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
                native[8..]
                    .copy_from_slice(&((duration % 1_000_000_000 / 1000) as i64).to_ne_bytes());
                socket_memory::write_output(value, length, &native[..count], count as u32)?;
                return Ok(0);
            }
            let tag = mochios_posix_client::socket::newlib_getsockopt_tag(level, option).map_err(
                |error| mochios_posix_client::newlib_errno::from_status(i64::from(error)),
            )?;
            if length.is_null() {
                return Err(EFAULT);
            }
            let capacity = socket_memory::read_length(length)?;
            if capacity > i32::MAX as u32 {
                return Err(EINVAL);
            }
            let count = (capacity as usize).min(core::mem::size_of::<c_int>());
            if count != 0 && value.is_null() {
                return Err(EFAULT);
            }
            let mut response = [0; 4];
            control(**entry, tag, &[], &mut response)?;
            let decoded = mochios_posix_client::socket::newlib_getsockopt_value(tag, &response)
                .map_err(|_| EIO)?;
            socket_memory::write_output(
                value,
                length,
                &decoded.to_ne_bytes()[..count],
                count as u32,
            )?;
            Ok(0)
        },
    );
    result_with_errno(result, -1)
}

pub(super) fn is_inet_datagram(entry: FdEntry) -> Result<bool, c_int> {
    let mut bytes = [0; wire::MAX_ADDRESS_LEN];
    let n = query_control(entry, wire::CONTROL_LOCAL_ADDRESS, &[], &mut bytes)?;
    Ok(matches!(
        wire::Address::decode(&bytes[..n]).map_err(|_| EIO)?,
        wire::Address::Ipv4 { .. }
    ))
}

pub(super) struct PendingSocketJob(pub(super) u32);
impl Drop for PendingSocketJob {
    fn drop(&mut self) {
        close_object_handle(self.0);
    }
}

unsafe fn connect_io(fd: c_int, address: *const c_void, length: u32) -> Result<c_int, c_int> {
    io_resources::with_initialized(
        || {
            Ok((
                with_fd_entry(fd)?,
                None::<PendingSocketJob>,
                [0u8; mochios_posix_client::socket::MAX_SOCKADDR_LEN],
            ))
        },
        |(entry, _, bytes)| {
            if !entry.handle.kind.is_socket() {
                return Err(mochios_posix_client::newlib_errno::from_status(-88));
            }
            if address.is_null() {
                return Err(EFAULT);
            }
            if length as usize > bytes.len() {
                return Err(EINVAL);
            }
            user_copy::read(address.cast(), &mut bytes[..length as usize])?;
            Ok(())
        },
        |(entry, pending, bytes)| unsafe {
            connect_entry(**entry, bytes.as_ptr().cast(), length, pending)
        },
    )
}

unsafe fn connect_entry(
    entry: FdEntry,
    address: *const c_void,
    length: u32,
    pending: &mut Option<PendingSocketJob>,
) -> Result<c_int, c_int> {
    if !entry.handle.kind.is_socket() {
        return Err(mochios_posix_client::newlib_errno::from_status(-88));
    }
    if address.is_null() {
        return Err(EFAULT);
    }
    if length as usize > mochios_posix_client::socket::MAX_SOCKADDR_LEN {
        return Err(EINVAL);
    }
    let bytes = unsafe { core::slice::from_raw_parts(address.cast::<u8>(), length as usize) };
    let address = mochios_posix_client::socket::decode_connect_sockaddr(bytes)
        .map_err(|error| mochios_posix_client::newlib_errno::from_status(i64::from(error)))?;
    let address = match address {
        mochios_posix_client::socket::ConnectAddress::Disconnect => {
            if entry.handle.kind != FdKind::ObjectDatagram {
                return Err(mochios_posix_client::newlib_errno::EOPNOTSUPP);
            }
            control(entry, wire::CONTROL_DISCONNECT, &[], &mut [])?;
            return Ok(0);
        }
        mochios_posix_client::socket::ConnectAddress::Peer(address) => address,
    };
    let (_, thread) = register_current_thread().ok_or(EAGAIN)?;
    let caught = thread.nonrestart_signal_generation.load(Ordering::Acquire);
    let mut wait = SocketWait::new(entry, syscall::HANDLE_SIGNAL_WRITABLE)?;
    let result = {
        let _native = defer_native_delivery();
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
        if let mochios_posix_client::socket::ConnectStarted::Pending(job) = &result {
            *pending = Some(PendingSocketJob(job.handle));
        }
        result
    };
    let mochios_posix_client::socket::ConnectStarted::Pending(job) = result else {
        return Ok(0);
    };
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
    io_resources::with_initialized(
        || {
            Ok((
                with_fd_entry(fd)?,
                None::<PendingFdReservation>,
                None::<PendingAccepted>,
                0usize,
            ))
        },
        |(entry, pending, _, capacity)| {
            if !entry.handle.kind.is_socket() {
                return Err(mochios_posix_client::newlib_errno::from_status(-88));
            }
            if !address.is_null() && length.is_null() {
                return Err(EFAULT);
            }
            *capacity = if address.is_null() {
                0
            } else {
                socket_memory::read_length(length)? as usize
            };
            let limit = process_fd_limit()?;
            *pending = Some(PendingFdReservation(
                state().fds.reserve_from(0, limit).map_err(|_| EMFILE)?,
            ));
            Ok(())
        },
        |(entry, pending, accepted, capacity)| unsafe {
            accept_entry(
                **entry,
                address,
                length,
                flags,
                *capacity,
                pending.as_ref().unwrap(),
                accepted,
            )
        },
    )
}

struct PendingAccepted {
    value: mochios_posix_client::socket::Accepted<u32>,
    installed: bool,
}
impl Drop for PendingAccepted {
    fn drop(&mut self) {
        if !self.installed {
            close_object_handle(self.value.socket.handle);
        }
    }
}

unsafe fn accept_entry(
    entry: FdEntry,
    address: *mut c_void,
    length: *mut u32,
    flags: c_int,
    capacity: usize,
    pending: &PendingFdReservation,
    accepted: &mut Option<PendingAccepted>,
) -> Result<c_int, c_int> {
    if !entry.handle.kind.is_socket() {
        return Err(mochios_posix_client::newlib_errno::from_status(-88));
    }
    if !address.is_null() && length.is_null() {
        return Err(EFAULT);
    }
    let client = posix_client().map_err(map_posix_client_error)?;
    stream_io(entry, syscall::HANDLE_SIGNAL_READABLE, || {
        let _native = defer_native_delivery();
        let value = client
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
            .map_err(map_posix_client_error)?;
        *accepted = Some(PendingAccepted {
            value,
            installed: false,
        });
        Ok(())
    })?;
    let accepted = accepted.as_mut().unwrap();
    let _native = defer_native_delivery();
    if !address.is_null() {
        let peer = accepted.value.peer_address().map_err(|_| EIO)?;
        let mut native = [0; mochios_posix_client::socket::MAX_SOCKADDR_LEN];
        let required =
            mochios_posix_client::socket::encode_sockaddr(peer, &mut native).map_err(|_| EIO)?;
        socket_memory::write_output(
            address,
            length,
            &native[..capacity.min(required)],
            required as u32,
        )?;
    }
    let local_flags = 2 | if flags & mochios_posix_client::socket::SOCK_CLOEXEC != 0 {
        O_CLOEXEC
    } else {
        0
    };
    let entry = object_entry(
        u64::from(accepted.value.socket.handle),
        accepted.value.socket.rights,
        entry.handle.kind,
        local_flags,
    );
    let result = state()
        .fds
        .commit_reservation(&pending.0, entry)
        .map_err(|_| EIO)?;
    accepted.installed = true;
    Ok(result)
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
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            if !entry.handle.kind.is_socket() {
                return Err(mochios_posix_client::newlib_errno::from_status(-88));
            }
            control(
                **entry,
                wire::CONTROL_LISTEN,
                &(backlog.max(0) as u32).to_le_bytes(),
                &mut [],
            )?;
            Ok(0)
        },
    );
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bind(fd: c_int, address: *const c_void, length: u32) -> c_int {
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            if !entry.handle.kind.is_socket() {
                return Err(mochios_posix_client::newlib_errno::from_status(-88));
            }
            if address.is_null() {
                return Err(EFAULT);
            }
            if length as usize > mochios_posix_client::socket::MAX_SOCKADDR_LEN {
                return Err(EINVAL);
            }
            let mut bytes = [0; mochios_posix_client::socket::MAX_SOCKADDR_LEN];
            let bytes = &mut bytes[..length as usize];
            user_copy::read(address.cast(), bytes)?;
            let decoded =
                mochios_posix_client::socket::decode_sockaddr(bytes).map_err(|error| {
                    mochios_posix_client::newlib_errno::from_status(i64::from(error))
                })?;
            let mut encoded = [0; wire::MAX_ADDRESS_LEN];
            let count = decoded.encode(&mut encoded).map_err(|_| EINVAL)?;
            control(**entry, wire::CONTROL_BIND, &encoded[..count], &mut [])?;
            Ok(0)
        },
    );
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int {
    let result = (|| {
        let (create, cloexec) = mochios_posix_client::socket::newlib_create(domain, kind, protocol)
            .map_err(|error| mochios_posix_client::newlib_errno::from_status(i64::from(error)))?;
        io_resources::with(
            || {
                let limit = process_fd_limit()?;
                let pending =
                    PendingFdReservation(state().fds.reserve_from(0, limit).map_err(|_| EMFILE)?);
                let client = posix_client().map_err(map_posix_client_error)?;
                let opened = if create.domain == wire::Domain::Ipv4
                    && matches!(create.kind, wire::Kind::Datagram | wire::Kind::Stream)
                {
                    let endpoint = client
                        .network_endpoint(close_object_handle)
                        .map_err(map_posix_client_error)?;
                    let _endpoint = PendingSocketJob(endpoint.handle);
                    let transport = SyscallEndpointTransport::new(endpoint.handle);
                    let factory = if create.kind == wire::Kind::Stream {
                        let mut scopes = 0;
                        for (name, scope) in [
                            ("net.connect", mochios_posix_client::network::CONNECT_SCOPE),
                            ("net.listen", mochios_posix_client::network::LISTEN_SCOPE),
                        ] {
                            let allowed = syscall::call2(
                                syscall::SyscallNumber::CapQuery,
                                name.as_ptr() as u64,
                                name.len() as u64,
                            )
                            .map_err(|error| {
                                mochios_posix_client::newlib_errno::from_status(error.raw())
                            })?;
                            if allowed != 0 {
                                scopes |= scope;
                            }
                        }
                        if scopes == 0 {
                            return Err(EACCES);
                        }
                        // Network authenticates the caller again at acquisition;
                        // this query merely chooses the requested scope subset.
                        mochios_posix_client::network::acquire_stream_factory(
                            &transport,
                            scopes,
                            close_object_handle,
                        )
                    } else {
                        mochios_posix_client::network::acquire_factory(
                            &transport,
                            close_object_handle,
                        )
                    }
                    .map_err(map_posix_client_error)?;
                    let _factory = PendingSocketJob(factory.handle);
                    if create.kind == wire::Kind::Stream {
                        client.open_inet_stream(create, factory, close_object_handle)
                    } else {
                        client.open_inet_datagram(create, factory, close_object_handle)
                    }
                    .map_err(map_posix_client_error)?
                } else {
                    client
                        .open_socket(create, close_object_handle)
                        .map_err(map_posix_client_error)?
                };
                Ok((
                    pending,
                    PendingHandles {
                        handles: [opened],
                        installed: false,
                    },
                ))
            },
            |(pending, opened)| {
                let _native = defer_native_delivery();
                let handle = opened.handles[0];
                let flags = 2 | if cloexec { O_CLOEXEC } else { 0 };
                let entry = object_entry(
                    u64::from(handle.handle),
                    handle.rights,
                    fd_kind(create.kind),
                    flags,
                );
                let fd = state()
                    .fds
                    .commit_reservation(&pending.0, entry)
                    .map_err(|_| EIO)?;
                opened.installed = true;
                Ok(fd)
            },
        )
    })();
    result_with_errno(result, -1)
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
        io_resources::with(
            || {
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
                Ok((
                    pending,
                    PendingHandles {
                        handles: opened,
                        installed: false,
                    },
                ))
            },
            |(pending, opened)| {
                let _native = defer_native_delivery();
                let flags = 2 | if cloexec { O_CLOEXEC } else { 0 };
                let entries = opened.handles.map(|opened| {
                    object_entry(
                        u64::from(opened.handle),
                        opened.rights,
                        fd_kind(create.kind),
                        flags,
                    )
                });
                // Neither label is an open FD until the output copy succeeds.
                pending.copy_descriptors(output)?;
                state()
                    .fds
                    .commit_pair([&pending.0[0], &pending.0[1]], entries)
                    .map_err(|_| EIO)?;
                opened.installed = true;
                Ok(0)
            },
        )
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

pub(super) unsafe fn socket_name(
    fd: c_int,
    address: *mut c_void,
    length: *mut u32,
    peer: bool,
) -> Result<c_int, c_int> {
    io_resources::with(
        || with_fd_entry(fd),
        |entry| socket_name_entry(**entry, address, length, peer),
    )
}

pub(super) fn socket_name_entry(
    entry: FdEntry,
    address: *mut c_void,
    length: *mut u32,
    peer: bool,
) -> Result<c_int, c_int> {
    if !entry.handle.kind.is_socket() {
        return Err(mochios_posix_client::newlib_errno::from_status(-88));
    }
    if address.is_null() || length.is_null() {
        return Err(EFAULT);
    }
    let capacity = socket_memory::read_length(length)? as usize;
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
    socket_memory::write_output(
        address,
        length,
        &native[..capacity.min(required)],
        required as u32,
    )?;
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
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            if !entry.handle.kind.is_socket() {
                return Err(mochios_posix_client::newlib_errno::from_status(-88));
            }
            if !(0..=2).contains(&how) {
                return Err(EINVAL);
            }
            control(
                **entry,
                wire::CONTROL_SHUTDOWN,
                &(how as u32).to_le_bytes(),
                &mut [],
            )?;
            Ok(0)
        },
    );
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

fn message_io(
    fd: c_int,
    buffer: u64,
    length: usize,
    flags: c_int,
    sending: bool,
) -> Result<isize, c_int> {
    // Stream payload/control calls use the retained descriptor directly.
    // Datagram jobs own additional Handles and keep the ordinary blocker.
    unsafe {
        io_resources::with_fork_opaque(
            || with_fd_entry(fd),
            |entry| entry.handle.kind == FdKind::ObjectSocket,
            |entry| message_entry(**entry, buffer, length, flags, sending),
        )
    }
}

pub(super) const MSG_EOR: c_int = 0x80;

fn fd_kind(kind: wire::Kind) -> FdKind {
    match kind {
        wire::Kind::Stream => FdKind::ObjectSocket,
        wire::Kind::Datagram => FdKind::ObjectDatagram,
        wire::Kind::SequencedPacket => FdKind::ObjectSeqPacket,
    }
}

pub(super) fn message_flags(entry: FdEntry, flags: c_int, sending: bool) -> c_int {
    // Each UNIX sequenced-packet send commits one complete record. MSG_EOR
    // explicitly states the same boundary; it has no byte-stream meaning.
    if sending && entry.handle.kind == FdKind::ObjectSeqPacket {
        flags & !MSG_EOR
    } else {
        flags
    }
}

pub(super) fn is_record(entry: FdEntry) -> bool {
    matches!(
        entry.handle.kind,
        FdKind::ObjectDatagram | FdKind::ObjectSeqPacket
    )
}

pub(super) fn is_datagram(entry: FdEntry) -> Result<bool, c_int> {
    Ok(entry.handle.kind == FdKind::ObjectDatagram)
}

pub(super) fn message_entry(
    entry: FdEntry,
    buffer: u64,
    length: usize,
    flags: c_int,
    sending: bool,
) -> Result<isize, c_int> {
    if !entry.handle.kind.is_socket() {
        return Err(mochios_posix_client::newlib_errno::from_status(-88));
    }
    if is_record(entry) {
        return super::socket_record::io(entry, buffer, length, flags, sending)
            .map(|record| record.count);
    }
    let options = mochios_posix_client::socket::message_options(flags, sending)
        .map_err(|_| mochios_posix_client::newlib_errno::EOPNOTSUPP)?;
    if length > isize::MAX as usize {
        return Err(EINVAL);
    }
    if length != 0 && buffer == 0 {
        return Err(EFAULT);
    }
    let empty_receive = length == 0 && !sending;
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
    // recv(0) still waits for data/EOF, unlike read(0). Inspect one byte into
    // private storage without consuming bytes or ancillary references.
    let mut probe = 0u8;
    let mut io = |offset: usize, remaining: usize| {
        let address = if empty_receive {
            (&mut probe as *mut u8) as u64
        } else {
            buffer.checked_add(offset as u64).ok_or(EFAULT)?
        };
        let result = stream_io_since_wait(
            entry,
            interests,
            thread,
            caught,
            0,
            options.dont_wait,
            &mut wait,
            || {
                let result = if options.peek || empty_receive {
                    syscall::raw_syscall4(
                        syscall::SyscallNumber::HandleReadAt,
                        entry.handle.lower_handle,
                        address,
                        remaining as u64,
                        0,
                    )
                } else {
                    syscall::raw_syscall3(
                        operation,
                        entry.handle.lower_handle,
                        address,
                        remaining as u64,
                    )
                };
                syscall_errno(result).and_then(|count| usize::try_from(count).map_err(|_| EIO))
            },
        );
        if sending && !options.no_signal && matches!(result, Err(EPIPE)) {
            io_resources::with(
                || Ok(()),
                |_| generate_thread_signal(posix_protocol::SIGNAL_PIPE),
            )?;
        }
        result
    };
    if empty_receive {
        match io(0, 1)? {
            0 | 1 => Ok(0),
            _ => Err(EIO),
        }
    } else if sending {
        let count = io(0, length)?;
        if count > length {
            return Err(EIO);
        }
        Ok(count as isize)
    } else {
        // UNIX-stream PEEK returns one available prefix even with WAITALL.
        // Repeating an offset inspection can cross an ancillary barrier or
        // combine data from different queue heads after another reader runs.
        mochios_posix_client::socket::receive(length, options.wait_all && !options.peek, io)
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

fn send_record_to(
    entry: FdEntry,
    buffer: *const c_void,
    length: usize,
    flags: c_int,
    address: *const c_void,
    address_length: u32,
) -> Result<isize, c_int> {
    if address.is_null() {
        return message_entry(entry, buffer as u64, length, flags, true);
    }
    if !entry.handle.kind.is_socket() {
        return Err(mochios_posix_client::newlib_errno::from_status(-88));
    }
    if !is_datagram(entry)? {
        return message_entry(entry, buffer as u64, length, flags, true);
    }
    if address_length as usize > mochios_posix_client::socket::MAX_SOCKADDR_LEN {
        return Err(EINVAL);
    }
    let mut bytes = [0; mochios_posix_client::socket::MAX_SOCKADDR_LEN];
    let bytes = &mut bytes[..address_length as usize];
    user_copy::read(address.cast(), bytes)?;
    let address = mochios_posix_client::socket::decode_sockaddr(bytes)
        .map_err(|error| mochios_posix_client::newlib_errno::from_status(i64::from(error)))?;
    if !matches!(address, wire::Address::UnixPath(_) | wire::Address::Ipv4 { .. }) {
        return Err(mochios_posix_client::newlib_errno::from_status(-97));
    }
    super::socket_record::send_to(entry, buffer as u64, length, flags, address)
        .map(|record| record.count)
}

#[unsafe(no_mangle)]
pub extern "C" fn sendto(
    fd: c_int,
    buffer: *const c_void,
    length: usize,
    flags: c_int,
    address: *const c_void,
    address_length: u32,
) -> isize {
    pthread_testcancel();
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| send_record_to(**entry, buffer, length, flags, address, address_length),
    );
    finish_io_cancellation(result_with_errno(result, -1))
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
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            socket_receive_address::receive(**entry, buffer, length, flags, address, address_length)
        },
    );
    finish_io_cancellation(result_with_errno(result, -1))
}
