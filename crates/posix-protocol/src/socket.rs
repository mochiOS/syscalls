//! Socket policy wire types. Domains/kinds are this userspace protocol's tags,
//! not native mnu ABI values. FD numbers, sockaddr padding and pointers never
//! enter these payloads. Attached Handles carry resource authority separately.

use super::ProtocolError;

pub const CREATE_LEN: usize = 16;
pub const NONBLOCKING: u32 = 1;
pub const ACCEPT_LEN: usize = 8;
pub const CONNECT_REPLY_LEN: usize = 8;

/// The reply contains no description/job identity. Authority to inspect or
/// cancel a pending attempt is carried only by the attached job Handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectReply {
    Connected,
    Waiting,
}

impl ConnectReply {
    pub fn encode(self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        if output.len() < CONNECT_REPLY_LEN {
            return Err(ProtocolError::BufferTooSmall);
        }
        output[..CONNECT_REPLY_LEN].fill(0);
        let phase: u32 = match self {
            Self::Connected => 0,
            Self::Waiting => 1,
        };
        output[..4].copy_from_slice(&phase.to_le_bytes());
        Ok(CONNECT_REPLY_LEN)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.len() != CONNECT_REPLY_LEN || input[4..] != [0; 4] {
            return Err(ProtocolError::InvalidLength);
        }
        match u32::from_le_bytes(
            input[..4]
                .try_into()
                .map_err(|_| ProtocolError::InvalidLength)?,
        ) {
            0 => Ok(Self::Connected),
            1 => Ok(Self::Waiting),
            _ => Err(ProtocolError::InvalidLength),
        }
    }
}

pub const fn connect_socket_rights() -> u64 {
    mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_TRANSFER
}

/// No data, seek/map, or duplication authority. Final release cancels only an
/// uncommitted attempt; it never shuts down an already-connected socket.
pub const fn connect_job_rights() -> u64 {
    mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_TRANSFER
}

/// HandleControl with empty input/output. Pending returns EAGAIN; a completed
/// attempt returns success or its stored error. Queries do not consume it.
pub const CONTROL_CONNECT_RESULT: u64 = u64::from_le_bytes(*b"SOCRES01");

/// Options apply to the new socket description. Listener blocking behavior
/// and descriptor-local CLOEXEC are not copied into this request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accept {
    pub options: u32,
}
impl Accept {
    pub fn encode(self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        if self.options & !NONBLOCKING != 0 {
            return Err(ProtocolError::InvalidLength);
        }
        if output.len() < ACCEPT_LEN {
            return Err(ProtocolError::BufferTooSmall);
        }
        output[..ACCEPT_LEN].fill(0);
        output[..4].copy_from_slice(&self.options.to_le_bytes());
        Ok(ACCEPT_LEN)
    }
    pub fn decode(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.len() != ACCEPT_LEN || input[4..] != [0; 4] {
            return Err(ProtocolError::InvalidLength);
        }
        let options = u32::from_le_bytes(
            input[..4]
                .try_into()
                .map_err(|_| ProtocolError::InvalidLength)?,
        );
        if options & !NONBLOCKING != 0 {
            return Err(ProtocolError::InvalidLength);
        }
        Ok(Self { options })
    }
}

pub const fn accept_listener_rights() -> u64 {
    mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_TRANSFER
}
/// Userspace control tags carried by generic HandleControl, not mnu opcodes.
pub const CONTROL_GET_OPTIONS: u64 = u64::from_le_bytes(*b"SOPOGT01");
pub const CONTROL_SET_OPTIONS: u64 = u64::from_le_bytes(*b"SOPOST01");
pub const CONTROL_SHUTDOWN: u64 = u64::from_le_bytes(*b"SOPSHD01");
pub const CONTROL_READINESS: u64 = u64::from_le_bytes(*b"SOPRDY01");
pub const CONTROL_STAT: u64 = u64::from_le_bytes(*b"SOPSTA01");
pub const CONTROL_LOCAL_ADDRESS: u64 = u64::from_le_bytes(*b"SOPLOC01");
pub const CONTROL_PEER_ADDRESS: u64 = u64::from_le_bytes(*b"SOPPER01");
pub const CONTROL_BIND: u64 = u64::from_le_bytes(*b"SOPBND01");
pub const CONTROL_LISTEN: u64 = u64::from_le_bytes(*b"SOPLSN01");
/// Empty input; one u32 Kind tag, not a libc SOCK_* value.
pub const CONTROL_KIND: u64 = u64::from_le_bytes(*b"SOPKND01");
/// Empty input; one u32 boolean reflecting the shared listener state.
pub const CONTROL_ACCEPTING: u64 = u64::from_le_bytes(*b"SOPACC01");
/// Empty input; u32 positive wire errno (or zero), atomically read and cleared.
pub const CONTROL_TAKE_ERROR: u64 = u64::from_le_bytes(*b"SOPERR01");
/// Empty input, u32 effective receive queue limit in bytes.
pub const CONTROL_GET_RECEIVE_CAPACITY: u64 = u64::from_le_bytes(*b"SORCGT01");
/// u32 requested receive queue limit, empty output. Service applies its bounds.
pub const CONTROL_SET_RECEIVE_CAPACITY: u64 = u64::from_le_bytes(*b"SORCST01");
/// Shared per-description send limit. Empty query returns one u32; setter
/// accepts one u32. These are userspace Provider tags, not native socket ABI.
pub const CONTROL_GET_SEND_CAPACITY: u64 = u64::from_le_bytes(*b"SOSCGT01");
pub const CONTROL_SET_SEND_CAPACITY: u64 = u64::from_le_bytes(*b"SOSCST01");
/// Receive timeout as u64 nanoseconds, zero means unlimited. No native kernel
/// socket policy: the client applies this shared description setting to waits.
pub const CONTROL_GET_RECEIVE_TIMEOUT: u64 = u64::from_le_bytes(*b"SORTGT01");
pub const CONTROL_SET_RECEIVE_TIMEOUT: u64 = u64::from_le_bytes(*b"SORTST01");
pub const CONTROL_GET_SEND_TIMEOUT: u64 = u64::from_le_bytes(*b"SOSTGT01");
pub const CONTROL_SET_SEND_TIMEOUT: u64 = u64::from_le_bytes(*b"SOSTST01");
pub const SHUTDOWN_READ: u32 = 0;
pub const SHUTDOWN_WRITE: u32 = 1;
pub const SHUTDOWN_BOTH: u32 = 2;
pub const READY_READ: u32 = 1;
pub const READY_WRITE: u32 = 2;
pub const READ_CLOSED: u32 = 4;
pub const WRITE_CLOSED: u32 = 8;
pub const WRITE_ERROR: u32 = 16;
pub const ERROR_PENDING: u32 = 32;
pub const READINESS_MASK: u32 =
    READY_READ | READY_WRITE | READ_CLOSED | WRITE_CLOSED | WRITE_ERROR | ERROR_PENDING;

/// No seek/map authority: a socket description is a duplex byte stream.
pub const fn descriptor_rights() -> u64 {
    mnu_abi::HANDLE_RIGHT_READ
        | mnu_abi::HANDLE_RIGHT_WRITE
        | mnu_abi::HANDLE_RIGHT_CONTROL
        | mnu_abi::HANDLE_RIGHT_WAIT
        | mnu_abi::HANDLE_RIGHT_DUPLICATE
        | mnu_abi::HANDLE_RIGHT_TRANSFER
}
pub const ADDRESS_HEADER_LEN: usize = 8;
/// Space for a NUL terminator (pathname) or namespace prefix (abstract) remains
/// in the libc sockaddr_un. Neither is included in the serialized name bytes.
pub const MAX_UNIX_NAME_BYTES: usize = 107;
pub const MAX_ADDRESS_LEN: usize = ADDRESS_HEADER_LEN + MAX_UNIX_NAME_BYTES;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    Unix = 1,
    Ipv4 = 2,
    Ipv6 = 3,
}
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Stream = 1,
    Datagram = 2,
    SequencedPacket = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Create {
    pub domain: Domain,
    pub kind: Kind,
    pub protocol: u32,
    pub options: u32,
}
impl Create {
    pub fn encode(self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        if self.options & !NONBLOCKING != 0 {
            return Err(ProtocolError::InvalidLength);
        }
        if output.len() < CREATE_LEN {
            return Err(ProtocolError::BufferTooSmall);
        }
        output[..CREATE_LEN].fill(0);
        output[..2].copy_from_slice(&(self.domain as u16).to_le_bytes());
        output[2..4].copy_from_slice(&(self.kind as u16).to_le_bytes());
        output[4..8].copy_from_slice(&self.protocol.to_le_bytes());
        output[8..12].copy_from_slice(&self.options.to_le_bytes());
        Ok(CREATE_LEN)
    }
    pub fn decode(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.len() != CREATE_LEN || input[12..].iter().any(|byte| *byte != 0) {
            return Err(ProtocolError::InvalidLength);
        }
        let domain = match u16::from_le_bytes(input[..2].try_into().unwrap()) {
            1 => Domain::Unix,
            2 => Domain::Ipv4,
            3 => Domain::Ipv6,
            _ => return Err(ProtocolError::InvalidLength),
        };
        let kind = match u16::from_le_bytes(input[2..4].try_into().unwrap()) {
            1 => Kind::Stream,
            2 => Kind::Datagram,
            3 => Kind::SequencedPacket,
            _ => return Err(ProtocolError::InvalidLength),
        };
        let options = u32::from_le_bytes(input[8..12].try_into().unwrap());
        if options & !NONBLOCKING != 0 {
            return Err(ProtocolError::InvalidLength);
        }
        Ok(Self {
            domain,
            kind,
            protocol: u32::from_le_bytes(input[4..8].try_into().unwrap()),
            options,
        })
    }
}

/// Ports/flow/scope are host-value integers serialized explicitly little-endian.
/// IP addresses remain network-order octets. The libc adapter converts sockaddr
/// network-order integers at its boundary, not inside mnu or this codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Address<'a> {
    UnixPath(&'a [u8]),
    UnixAbstract(&'a [u8]),
    UnixUnnamed,
    Ipv4 {
        address: [u8; 4],
        port: u16,
    },
    Ipv6 {
        address: [u8; 16],
        port: u16,
        flow_info: u32,
        scope_id: u32,
    },
}
impl<'a> Address<'a> {
    pub fn encode(self, output: &mut [u8]) -> Result<usize, ProtocolError> {
        let (domain, form, length) = match self {
            Self::UnixPath(name)
                if !name.is_empty() && !name.contains(&0) && name.len() <= MAX_UNIX_NAME_BYTES =>
            {
                (Domain::Unix, 0, name.len())
            }
            Self::UnixAbstract(name) if name.len() <= MAX_UNIX_NAME_BYTES => {
                (Domain::Unix, 1, name.len())
            }
            Self::UnixUnnamed => (Domain::Unix, 2, 0),
            Self::Ipv4 { .. } => (Domain::Ipv4, 0, 6),
            Self::Ipv6 { .. } => (Domain::Ipv6, 0, 26),
            _ => return Err(ProtocolError::InvalidLength),
        };
        let total = ADDRESS_HEADER_LEN + length;
        if output.len() < total {
            return Err(ProtocolError::BufferTooSmall);
        }
        output[..total].fill(0);
        output[..2].copy_from_slice(&(domain as u16).to_le_bytes());
        output[2] = form;
        output[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        let data = &mut output[ADDRESS_HEADER_LEN..total];
        match self {
            Self::UnixPath(name) | Self::UnixAbstract(name) => data.copy_from_slice(name),
            Self::UnixUnnamed => (),
            Self::Ipv4 { address, port } => {
                data[..2].copy_from_slice(&port.to_le_bytes());
                data[2..].copy_from_slice(&address);
            }
            Self::Ipv6 {
                address,
                port,
                flow_info,
                scope_id,
            } => {
                data[..2].copy_from_slice(&port.to_le_bytes());
                data[2..6].copy_from_slice(&flow_info.to_le_bytes());
                data[6..10].copy_from_slice(&scope_id.to_le_bytes());
                data[10..].copy_from_slice(&address);
            }
        }
        Ok(total)
    }
    pub fn decode(input: &'a [u8]) -> Result<Self, ProtocolError> {
        if input.len() < ADDRESS_HEADER_LEN || input[3] != 0 {
            return Err(ProtocolError::InvalidLength);
        }
        let data = &input[ADDRESS_HEADER_LEN..];
        if u32::from_le_bytes(input[4..8].try_into().unwrap()) as usize != data.len() {
            return Err(ProtocolError::InvalidLength);
        }
        match (u16::from_le_bytes(input[..2].try_into().unwrap()), input[2]) {
            (1, 0)
                if !data.is_empty() && !data.contains(&0) && data.len() <= MAX_UNIX_NAME_BYTES =>
            {
                Ok(Self::UnixPath(data))
            }
            (1, 1) if data.len() <= MAX_UNIX_NAME_BYTES => Ok(Self::UnixAbstract(data)),
            (1, 2) if data.is_empty() => Ok(Self::UnixUnnamed),
            (2, 0) if data.len() == 6 => Ok(Self::Ipv4 {
                port: u16::from_le_bytes(data[..2].try_into().unwrap()),
                address: data[2..].try_into().unwrap(),
            }),
            (3, 0) if data.len() == 26 => Ok(Self::Ipv6 {
                port: u16::from_le_bytes(data[..2].try_into().unwrap()),
                flow_info: u32::from_le_bytes(data[2..6].try_into().unwrap()),
                scope_id: u32::from_le_bytes(data[6..10].try_into().unwrap()),
                address: data[10..].try_into().unwrap(),
            }),
            _ => Err(ProtocolError::InvalidLength),
        }
    }
}
