//! Socket creation is control-plane IPC. Data, shutdown and readiness use the
//! returned native Provider Handles; client FD numbers never enter the wire.

use crate::{Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport};
use mochios_posix_protocol::{self as protocol, socket as wire};

pub const SOCK_NONBLOCK: i32 = 0x800;
pub const SOCK_CLOEXEC: i32 = 0x80000;

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

pub fn poll_events(bits: u32, events: i16) -> i16 {
    let mut result = 0;
    if bits & wire::READY_READ != 0 {
        result |= events & crate::multiplex::NORMAL_READ_EVENTS;
    }
    if bits & (wire::READY_WRITE | wire::WRITE_CLOSED) != 0 {
        result |= events & crate::multiplex::NORMAL_WRITE_EVENTS;
    }
    if bits & wire::WRITE_ERROR != 0 {
        result |= 0x8;
    }
    if bits & (wire::READ_CLOSED | wire::WRITE_CLOSED) == (wire::READ_CLOSED | wire::WRITE_CLOSED) {
        result |= 0x10;
    }
    result
}

impl<T: ObjectTransport> Client<T> {
    /// Returns ownership of two receiver-local Handles. The caller must reserve
    /// both local FD slots before requesting resources and close both Handles
    /// if installation fails. `close` releases every attachment on failed or
    /// malformed replies, including owned attachments returned on transport errors.
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
        let outcome =
            self.request_with_handles(protocol::OP_SOCKET_PAIR, 0, &payload, &mut [], &mut handles);
        if matches!(outcome, Ok(0)) && handles.len() == 2 {
            let first = handles.get(0).unwrap();
            let second = handles.get(1).unwrap();
            if first.rights == wire::descriptor_rights()
                && second.rights == wire::descriptor_rights()
                && first.handle != second.handle
            {
                return Ok([first, second]);
            }
        }
        // ObjectTransport guarantees each returned entry owns a received
        // reference, never a borrowed outgoing Handle (this request has none).
        for (index, received) in handles.iter().enumerate() {
            if !handles
                .iter()
                .take(index)
                .any(|earlier| earlier.handle == received.handle)
            {
                close(received.handle);
            }
        }
        Err(outcome.err().unwrap_or(ClientError::MismatchedResponse))
    }
}
