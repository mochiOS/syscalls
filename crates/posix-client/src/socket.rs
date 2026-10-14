//! Socket creation is control-plane IPC. Data, shutdown and readiness use the
//! returned native Provider Handles; client FD numbers never enter the wire.

use crate::{Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport};
use mochios_posix_protocol::{self as protocol, socket as wire};

pub const SOCK_NONBLOCK: i32 = 0x800;
pub const SOCK_CLOEXEC: i32 = 0x80000;
pub const MSG_DONTWAIT: i32 = 0x40;
pub const MSG_PEEK: i32 = 0x2;
pub const MSG_WAITALL: i32 = 0x100;
pub const MSG_NOSIGNAL: i32 = 0x4000;
pub const MAX_SOCKADDR_LEN: usize = 110;

/// timeval is decoded at libc's boundary; only a duration enters the wire.
pub fn socket_timeout_nanoseconds(seconds: i64, microseconds: i64) -> Result<u64, i32> {
    if seconds < 0 || !(0..1_000_000).contains(&microseconds) {
        return Err(-22);
    }
    (seconds as u64)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(microseconds as u64 * 1000))
        .ok_or(-22)
}

/// Keep one absolute deadline across short reads, spurious wakes and retries.
/// u64::MAX remains reserved for the native infinite-wait marker.
pub fn socket_deadline(started: u64, duration: u64) -> u64 {
    if duration == 0 {
        u64::MAX
    } else {
        started.saturating_add(duration).min(u64::MAX - 1)
    }
}

/// Query options currently supplied by the socket Provider. C ABI option
/// numbers stay on this side of HandleControl's userspace wire tags.
pub fn newlib_getsockopt_tag(level: i32, option: i32) -> Result<u64, i32> {
    match (level, option) {
        (1, 3) => Ok(wire::CONTROL_KIND),       // SOL_SOCKET / SO_TYPE
        (1, 4) => Ok(wire::CONTROL_TAKE_ERROR), // SOL_SOCKET / SO_ERROR
        (1, 7) => Ok(wire::CONTROL_GET_SEND_CAPACITY), // SOL_SOCKET / SO_SNDBUF
        (1, 8) => Ok(wire::CONTROL_GET_RECEIVE_CAPACITY), // SOL_SOCKET / SO_RCVBUF
        (1, 30) => Ok(wire::CONTROL_ACCEPTING), // SOL_SOCKET / SO_ACCEPTCONN
        _ => Err(-92),
    }
}

pub fn newlib_getsockopt_value(tag: u64, bytes: &[u8]) -> Result<i32, i32> {
    let value = u32::from_le_bytes(bytes.try_into().map_err(|_| -5)?);
    match (tag, value) {
        (wire::CONTROL_KIND, 1) => Ok(1), // Stream
        (wire::CONTROL_KIND, 2) => Ok(2), // Datagram
        (wire::CONTROL_KIND, 3) => Ok(5), // SequencedPacket
        (wire::CONTROL_ACCEPTING, 0 | 1) => Ok(value as i32),
        (wire::CONTROL_GET_RECEIVE_CAPACITY, 1..=0x7fff_ffff) => Ok(value as i32),
        (wire::CONTROL_GET_SEND_CAPACITY, 1..=0x7fff_ffff) => Ok(value as i32),
        (wire::CONTROL_TAKE_ERROR, 0) => Ok(0),
        (wire::CONTROL_TAKE_ERROR, 1..=0x7fff_ffff) => {
            Ok(crate::newlib_errno::from_status(i64::from(value)))
        }
        _ => Err(-5),
    }
}

pub fn newlib_setsockopt(level: i32, option: i32, value: i32) -> Result<(u64, [u8; 4]), i32> {
    match (level, option) {
        (1, 7) if value >= 0 => Ok((
            wire::CONTROL_SET_SEND_CAPACITY,
            (value as u32).to_le_bytes(),
        )),
        (1, 7) => Err(-22),
        (1, 8) if value >= 0 => Ok((
            wire::CONTROL_SET_RECEIVE_CAPACITY,
            (value as u32).to_le_bytes(),
        )),
        (1, 8) => Err(-22),
        _ => Err(-92),
    }
}

/// Pending owns one received notification reference, not a local FD. Wait on
/// its native READABLE signal, query CONTROL_CONNECT_RESULT, and close on every
/// exit path. Dropping the final reference cancels an uncommitted attempt.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "release a pending connection job on completion or interruption"]
pub enum ConnectStarted<H> {
    Connected,
    Pending(ObjectHandleAttachment<H>),
}

/// One received socket reference plus validated, owned peer-address bytes.
/// The caller reserves a local FD before requesting this resource and releases
/// `socket.handle` if FD installation fails. No FD number enters the protocol.
#[derive(Debug, PartialEq, Eq)]
pub struct Accepted<H> {
    pub socket: ObjectHandleAttachment<H>,
    address: [u8; wire::MAX_ADDRESS_LEN],
    address_len: usize,
}
impl<H> Accepted<H> {
    pub fn peer_address(&self) -> Result<wire::Address<'_>, protocol::ProtocolError> {
        wire::Address::decode(&self.address[..self.address_len])
    }
}

/// A connect-only operation selector, distinct from a peer or source address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectAddress<'a> {
    Disconnect,
    Peer(wire::Address<'a>),
}

/// AF_UNSPEC is an operation selector only for connect, not a peer/source
/// address that bind/sendto or received-address codecs should accept.
pub fn decode_connect_sockaddr(input: &[u8]) -> Result<ConnectAddress<'_>, i32> {
    if input.len() > MAX_SOCKADDR_LEN {
        return Err(-22);
    }
    let family = input.get(..2).ok_or(-22)?;
    if u16::from_le_bytes(family.try_into().unwrap()) == 0 {
        Ok(ConnectAddress::Disconnect)
    } else {
        decode_sockaddr(input).map(ConnectAddress::Peer)
    }
}

/// Decode the C ABI without casting potentially unaligned bytes to sockaddr.
/// UNIX abstract names are binary; pathname terminators and IP padding are not
/// transmitted. Path traversal and authorization belong to the service layer.
pub fn decode_sockaddr(input: &[u8]) -> Result<wire::Address<'_>, i32> {
    let family = input.get(..2).ok_or(-22)?;
    match u16::from_le_bytes(family.try_into().unwrap()) {
        1 => {
            if input.len() > MAX_SOCKADDR_LEN {
                return Err(-22);
            }
            let name = &input[2..];
            if name.is_empty() {
                return Ok(wire::Address::UnixUnnamed);
            }
            if name[0] == 0 {
                return Ok(wire::Address::UnixAbstract(&name[1..]));
            }
            let length = name
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(name.len());
            if length > wire::MAX_UNIX_NAME_BYTES {
                return Err(-36);
            }
            Ok(wire::Address::UnixPath(&name[..length]))
        }
        2 => {
            let bytes = input.get(..16).ok_or(-22)?;
            Ok(wire::Address::Ipv4 {
                address: bytes[4..8].try_into().unwrap(),
                port: u16::from_be_bytes(bytes[2..4].try_into().unwrap()),
            })
        }
        10 => {
            let bytes = input.get(..28).ok_or(-22)?;
            Ok(wire::Address::Ipv6 {
                address: bytes[8..24].try_into().unwrap(),
                port: u16::from_be_bytes(bytes[2..4].try_into().unwrap()),
                flow_info: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
                scope_id: u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
            })
        }
        _ => Err(-97),
    }
}

/// Serialize mochiOS's C sockaddr layout; wire tags, port encoding and padding
/// are independent of this ABI. The caller performs any output truncation.
pub fn encode_sockaddr(address: wire::Address<'_>, output: &mut [u8]) -> Result<usize, i32> {
    let mut validated = [0; wire::MAX_ADDRESS_LEN];
    address.encode(&mut validated).map_err(|_| -22)?;
    let (family, length): (u16, usize) = match address {
        wire::Address::UnixUnnamed => (1, 2),
        wire::Address::UnixPath(name) | wire::Address::UnixAbstract(name) => (1, 3 + name.len()),
        wire::Address::Ipv4 { .. } => (2, 16),
        wire::Address::Ipv6 { .. } => (10, 28),
    };
    if output.len() < length {
        return Err(-22);
    }
    output[..length].fill(0);
    output[..2].copy_from_slice(&family.to_le_bytes());
    match address {
        wire::Address::UnixUnnamed => (),
        wire::Address::UnixPath(name) => output[2..2 + name.len()].copy_from_slice(name),
        wire::Address::UnixAbstract(name) => output[3..length].copy_from_slice(name),
        wire::Address::Ipv4 { address, port } => {
            output[2..4].copy_from_slice(&port.to_be_bytes());
            output[4..8].copy_from_slice(&address);
        }
        wire::Address::Ipv6 {
            address,
            port,
            flow_info,
            scope_id,
        } => {
            output[2..4].copy_from_slice(&port.to_be_bytes());
            output[4..8].copy_from_slice(&flow_info.to_be_bytes());
            output[8..24].copy_from_slice(&address);
            output[24..28].copy_from_slice(&scope_id.to_le_bytes());
        }
    }
    Ok(length)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageOptions {
    pub peek: bool,
    pub dont_wait: bool,
    pub wait_all: bool,
    pub no_signal: bool,
}

/// Unsupported semantics are rejected before consuming data. PEEK selects
/// native indexed inspection, never destructive read or unrestricted control.
pub fn message_options(flags: i32, sending: bool) -> Result<MessageOptions, i32> {
    let supported = MSG_DONTWAIT
        | if sending {
            MSG_NOSIGNAL
        } else {
            MSG_WAITALL | MSG_PEEK
        };
    if flags & !supported != 0 {
        return Err(-95);
    }
    Ok(MessageOptions {
        peek: flags & MSG_PEEK != 0,
        dont_wait: flags & MSG_DONTWAIT != 0,
        wait_all: flags & MSG_WAITALL != 0,
        no_signal: flags & MSG_NOSIGNAL != 0,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReceiveError<E> {
    InvalidResult,
    Io(E),
}

/// Preserve every transferred prefix on EOF, interruption or later failure.
/// The callback handles waiting/cancellation; no shared flag mutation is needed.
pub fn receive<E>(
    length: usize,
    wait_all: bool,
    mut io: impl FnMut(usize, usize) -> Result<usize, E>,
) -> Result<usize, ReceiveError<E>> {
    if length == 0 {
        return Ok(0);
    }
    let mut received = 0;
    loop {
        let remaining = length - received;
        let count = match io(received, remaining) {
            Ok(count) if count <= remaining => count,
            Ok(_) => {
                return if received == 0 {
                    Err(ReceiveError::InvalidResult)
                } else {
                    Ok(received)
                };
            }
            Err(error) => {
                return if received == 0 {
                    Err(ReceiveError::Io(error))
                } else {
                    Ok(received)
                };
            }
        };
        received += count;
        if !wait_all || count == 0 || received == length {
            return Ok(received);
        }
    }
}

/// C socket tags are translated here, never exposed as native mnu flags.
pub fn newlib_create(domain: i32, kind: i32, protocol: i32) -> Result<(wire::Create, bool), i32> {
    if protocol < 0 || kind & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(-22);
    }
    let domain = match domain {
        1 => wire::Domain::Unix,
        2 => wire::Domain::Ipv4,
        10 => wire::Domain::Ipv6,
        _ => return Err(-97),
    };
    let socket_kind = match kind & 0xf {
        1 => wire::Kind::Stream,
        2 => wire::Kind::Datagram,
        5 => wire::Kind::SequencedPacket,
        _ => return Err(-94),
    };
    Ok((
        wire::Create {
            domain,
            kind: socket_kind,
            protocol: protocol as u32,
            options: if kind & SOCK_NONBLOCK != 0 {
                wire::NONBLOCKING
            } else {
                0
            },
        },
        kind & SOCK_CLOEXEC != 0,
    ))
}

pub fn decode_readiness(bytes: &[u8]) -> Result<u32, i32> {
    let bits = u32::from_le_bytes(bytes.try_into().map_err(|_| -5)?);
    if bits & !wire::READINESS_MASK != 0 {
        return Err(-5);
    }
    Ok(bits)
}

pub fn poll_events(bits: u32, events: i16) -> i16 {
    let mut result = 0;
    if bits & wire::READY_READ != 0 {
        result |= events & crate::multiplex::NORMAL_READ_EVENTS;
    }
    if bits & (wire::READY_WRITE | wire::WRITE_CLOSED) != 0 {
        result |= events & crate::multiplex::NORMAL_WRITE_EVENTS;
    }
    if bits & wire::ERROR_PENDING != 0 {
        result |= 0x8;
    }
    if bits & (wire::READ_CLOSED | wire::WRITE_CLOSED) == (wire::READ_CLOSED | wire::WRITE_CLOSED) {
        result |= 0x10;
    }
    result
}

impl<T: ObjectTransport> Client<T> {
    /// Register a one-shot notification for additional receive bytes or a
    /// terminal condition. Only explicitly attached READ authority is used.
    /// Closing the returned Handle cancels the registration and its socket lease.
    pub fn wait_socket_receive(
        &self,
        socket: ObjectHandleAttachment<T::Handle>,
        minimum: u64,
        mut close: impl FnMut(T::Handle),
    ) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>>
    where
        T::Handle: Copy + Default + Eq,
    {
        let rights = wire::receive_wait_socket_rights();
        if socket.handle == T::Handle::default() || socket.rights & rights != rights {
            return Err(ClientError::Remote(-13));
        }
        if minimum == 0 {
            return Err(ClientError::Remote(-22));
        }
        let mut handles = ObjectHandles::new();
        handles
            .push(ObjectHandleAttachment {
                handle: socket.handle,
                rights,
            })
            .map_err(|_| ClientError::RequestTooLarge)?;
        let borrowed = handles.clone();
        let result = self.request_with_handles(
            protocol::OP_SOCKET_RECEIVE_WAIT,
            0,
            &minimum.to_le_bytes(),
            &mut [],
            &mut handles,
        );
        if matches!(result, Ok(0)) && handles.len() == 1 {
            let job = handles.get(0).unwrap();
            if job.handle != T::Handle::default()
                && job.handle != socket.handle
                && job.rights == wire::receive_wait_job_rights()
            {
                return Ok(job);
            }
        }
        crate::drain_received_handles(&mut handles, &borrowed, &mut close);
        Err(result.err().unwrap_or(ClientError::MismatchedResponse))
    }

    /// Attach explicit socket authority; never send a FD, PID, or object ID.
    /// Shared description flags decide whether a full backlog can wait.
    pub fn connect_socket(
        &self,
        socket: ObjectHandleAttachment<T::Handle>,
        address: wire::Address<'_>,
        mut close: impl FnMut(T::Handle),
    ) -> Result<ConnectStarted<T::Handle>, ClientError<T::Error>>
    where
        T::Handle: Eq + Default,
    {
        let required = wire::connect_socket_rights();
        if socket.handle == T::Handle::default() || socket.rights & required != required {
            return Err(ClientError::Remote(-13));
        }
        let mut payload = [0; wire::MAX_ADDRESS_LEN];
        let payload_len = address
            .encode(&mut payload)
            .map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        handles
            .push(ObjectHandleAttachment {
                handle: socket.handle,
                rights: required,
            })
            .map_err(|_| ClientError::RequestTooLarge)?;
        let mut reply = [0; wire::CONNECT_REPLY_LEN];
        let borrowed = handles.clone();
        let result = self.request_with_handles(
            protocol::OP_SOCKET_CONNECT,
            0,
            &payload[..payload_len],
            &mut reply,
            &mut handles,
        );
        if let Ok(length) = result {
            match wire::ConnectReply::decode(&reply[..length]) {
                Ok(wire::ConnectReply::Connected) if handles.is_empty() => {
                    return Ok(ConnectStarted::Connected);
                }
                Ok(wire::ConnectReply::Waiting) if handles.len() == 1 => {
                    let job = handles.get(0).unwrap();
                    if job.handle != T::Handle::default()
                        && job.handle != socket.handle
                        && job.rights == wire::connect_job_rights()
                    {
                        return Ok(ConnectStarted::Pending(job));
                    }
                }
                _ => {}
            }
        }
        // Transport replaced borrowed outgoing authority with owned received
        // references, including on errors. Reclaim malformed replies once.
        crate::drain_received_handles(&mut handles, &borrowed, &mut close);
        Err(result.err().unwrap_or(ClientError::MismatchedResponse))
    }

    /// Nonblocking queue operation. The native listener's WAIT authority is
    /// used separately by libc for a blocking accept, cancellation and EINTR.
    pub fn accept_socket(
        &self,
        listener: ObjectHandleAttachment<T::Handle>,
        request: wire::Accept,
        mut close: impl FnMut(T::Handle),
    ) -> Result<Accepted<T::Handle>, ClientError<T::Error>>
    where
        T::Handle: Eq + Default,
    {
        let required = wire::accept_listener_rights();
        if listener.handle == T::Handle::default() || listener.rights & required != required {
            return Err(ClientError::Remote(-13));
        }
        let mut payload = [0; wire::ACCEPT_LEN];
        request
            .encode(&mut payload)
            .map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        handles
            .push(ObjectHandleAttachment {
                handle: listener.handle,
                rights: required,
            })
            .map_err(|_| ClientError::RequestTooLarge)?;
        let mut address = [0; wire::MAX_ADDRESS_LEN];
        let borrowed = handles.clone();
        let result = self.request_with_handles(
            protocol::OP_SOCKET_ACCEPT,
            0,
            &payload,
            &mut address,
            &mut handles,
        );
        if let Ok(length) = result {
            if wire::Address::decode(&address[..length]).is_ok() && handles.len() == 1 {
                let received = handles.get(0).unwrap();
                if received.handle != T::Handle::default()
                    && received.handle != listener.handle
                    && received.rights == wire::descriptor_rights()
                {
                    return Ok(Accepted {
                        socket: received,
                        address,
                        address_len: length,
                    });
                }
            }
        }
        // ObjectTransport replaces borrowed outgoing attachments with owned
        // reply references even on failure. Never close the source listener.
        crate::drain_received_handles(&mut handles, &borrowed, &mut close);
        Err(result.err().unwrap_or(ClientError::MismatchedResponse))
    }

    /// Return ownership of one unconnected socket Handle, never a hidden pair.
    pub fn open_socket(
        &self,
        create: wire::Create,
        mut close: impl FnMut(T::Handle),
    ) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>>
    where
        T::Handle: Eq,
    {
        let mut payload = [0; wire::CREATE_LEN];
        create.encode(&mut payload).map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        let borrowed = handles.clone();
        let outcome = self.request_with_handles(
            protocol::OP_SOCKET_CREATE,
            0,
            &payload,
            &mut [],
            &mut handles,
        );
        if matches!(outcome, Ok(0)) && handles.len() == 1 {
            let received = handles.get(0).unwrap();
            if received.handle != T::Handle::default()
                && received.rights == wire::descriptor_rights()
            {
                return Ok(received);
            }
        }
        crate::drain_received_handles(&mut handles, &borrowed, &mut close);
        Err(outcome.err().unwrap_or(ClientError::MismatchedResponse))
    }

    /// Returns ownership of two receiver-local Handles. The caller must reserve
    /// both local FD slots before requesting resources and close both Handles
    /// if installation fails. `close` releases distinct valid owned attachments
    /// on failed or malformed replies, including transport errors.
    pub fn socket_pair(
        &self,
        create: wire::Create,
        mut close: impl FnMut(T::Handle),
    ) -> Result<[ObjectHandleAttachment<T::Handle>; 2], ClientError<T::Error>>
    where
        T::Handle: Eq,
    {
        let mut payload = [0; wire::CREATE_LEN];
        create.encode(&mut payload).map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        let borrowed = handles.clone();
        let outcome =
            self.request_with_handles(protocol::OP_SOCKET_PAIR, 0, &payload, &mut [], &mut handles);
        if matches!(outcome, Ok(0)) && handles.len() == 2 {
            let first = handles.get(0).unwrap();
            let second = handles.get(1).unwrap();
            if first.handle != T::Handle::default()
                && second.handle != T::Handle::default()
                && first.rights == wire::descriptor_rights()
                && second.rights == wire::descriptor_rights()
                && first.handle != second.handle
            {
                return Ok([first, second]);
            }
        }
        // ObjectTransport guarantees each returned entry owns a received
        // reference, never a borrowed outgoing Handle (this request has none).
        crate::drain_received_handles(&mut handles, &borrowed, &mut close);
        Err(outcome.err().unwrap_or(ClientError::MismatchedResponse))
    }
}
