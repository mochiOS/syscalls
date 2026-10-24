use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::PacketError;

pub const EPHEMERAL_PORT_START: u16 = 49_152;
pub const EPHEMERAL_PORT_END: u16 = 65_535;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: &'a [u8],
}
impl<'a> UdpDatagram<'a> {
    pub fn decode(source: [u8; 4], destination: [u8; 4], b: &'a [u8]) -> Result<Self, PacketError> {
        if b.len() < 8 {
            return Err(PacketError::Truncated);
        }
        let len = u16::from_be_bytes([b[4], b[5]]) as usize;
        if len < 8 || len > b.len() {
            return Err(PacketError::InvalidLength);
        }
        let received = u16::from_be_bytes([b[6], b[7]]);
        if received != 0 {
            let mut pseudo = [0u8; 12];
            pseudo[..4].copy_from_slice(&source);
            pseudo[4..8].copy_from_slice(&destination);
            pseudo[9] = 17;
            pseudo[10..12].copy_from_slice(&(len as u16).to_be_bytes());
            if !checksum_parts_valid(&pseudo, &b[..len]) {
                return Err(PacketError::InvalidChecksum);
            }
        }
        Ok(Self {
            source_port: u16::from_be_bytes([b[0], b[1]]),
            destination_port: u16::from_be_bytes([b[2], b[3]]),
            payload: &b[8..len],
        })
    }
    pub fn encode(
        self,
        source: [u8; 4],
        destination: [u8; 4],
        out: &mut [u8],
    ) -> Result<usize, PacketError> {
        let len = 8usize
            .checked_add(self.payload.len())
            .ok_or(PacketError::InvalidLength)?;
        let len16 = u16::try_from(len).map_err(|_| PacketError::InvalidLength)?;
        if out.len() < len {
            return Err(PacketError::Truncated);
        }
        out[..8].fill(0);
        out[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        out[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
        out[4..6].copy_from_slice(&len16.to_be_bytes());
        out[8..len].copy_from_slice(self.payload);
        let mut pseudo = [0u8; 12];
        pseudo[..4].copy_from_slice(&source);
        pseudo[4..8].copy_from_slice(&destination);
        pseudo[9] = 17;
        pseudo[10..12].copy_from_slice(&len16.to_be_bytes());
        let mut sum = partial(&pseudo) + partial(&out[..len]);
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        let mut c = !(sum as u16);
        if c == 0 {
            c = 0xffff
        }
        out[6..8].copy_from_slice(&c.to_be_bytes());
        Ok(len)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpPacket {
    pub source_address: [u8; 4],
    pub destination_address: [u8; 4],
    pub source_port: u16,
    pub destination_port: u16,
    pub payload: Vec<u8>,
}

/// Worker-private identity, not an IPC capability, client FD or port lookup
/// authority. A service must select it through its authenticated Handle owner.
/// IDs are never reused within a table, including after a port is rebound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpSocketId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpEndpoint {
    pub address: [u8; 4],
    pub port: u16,
}
impl UdpEndpoint {
    fn overlaps(self, other: Self) -> bool {
        self.port == other.port
            && (self.address == [0; 4] || other.address == [0; 4] || self.address == other.address)
    }
}

struct UdpBinding {
    id: UdpSocketId,
    local: UdpEndpoint,
    peer: Option<UdpEndpoint>,
    received: VecDeque<UdpPacket>,
}

pub struct UdpSocketTable {
    bindings: Vec<UdpBinding>,
    socket_limit: usize,
    queue_limit: usize,
    payload_limit: usize,
    next_ephemeral: u16,
    next_id: u64,
}

impl UdpSocketTable {
    pub fn new(socket_limit: usize, queue_limit: usize, payload_limit: usize) -> Self {
        Self {
            bindings: Vec::new(),
            socket_limit,
            queue_limit,
            payload_limit,
            next_ephemeral: EPHEMERAL_PORT_START,
            next_id: 1,
        }
    }

    /// Compatibility for the stack's private DHCP/DNS wildcard bindings.
    /// Port-based methods never select an address-specific application socket.
    pub fn bind(&mut self, requested_port: u16) -> Result<u16, PacketError> {
        let id = self.bind_endpoint([0; 4], requested_port)?;
        Ok(self.local_endpoint(id)?.port)
    }

    /// Address availability, privileged-port policy and Capability checks belong
    /// to the service. This table enforces overlap, bounded storage and identity.
    /// No SO_REUSEADDR/SO_REUSEPORT sharing is implicitly enabled.
    pub fn bind_endpoint(
        &mut self,
        address: [u8; 4],
        requested_port: u16,
    ) -> Result<UdpSocketId, PacketError> {
        if self.bindings.len() >= self.socket_limit || self.next_id == u64::MAX {
            return Err(PacketError::Capacity);
        }
        let port = if requested_port == 0 {
            self.allocate_ephemeral(address)
                .ok_or(PacketError::Capacity)?
        } else {
            if self.conflicts(UdpEndpoint {
                address,
                port: requested_port,
            }) {
                return Err(PacketError::Mismatch);
            }
            requested_port
        };
        // Complete every allocation before publishing the binding or its ID.
        self.bindings
            .try_reserve(1)
            .map_err(|_| PacketError::Capacity)?;
        let mut received = VecDeque::new();
        received
            .try_reserve(self.queue_limit)
            .map_err(|_| PacketError::Capacity)?;
        let id = UdpSocketId(self.next_id);
        self.bindings.push(UdpBinding {
            id,
            local: UdpEndpoint { address, port },
            peer: None,
            received,
        });
        self.next_id += 1;
        Ok(id)
    }

    pub fn local_endpoint(&self, id: UdpSocketId) -> Result<UdpEndpoint, PacketError> {
        Ok(self.binding(id)?.local)
    }

    pub fn peer(&self, id: UdpSocketId) -> Result<Option<UdpEndpoint>, PacketError> {
        Ok(self.binding(id)?.peer)
    }

    /// Select the default remote endpoint and filter future arrivals by both
    /// source address and source port. Already accepted records remain queued;
    /// discarding them is a separate, higher-level socket policy decision.
    /// None removes only the association, preserving binding and queued data.
    /// Route, address and permission validation belongs to the service caller.
    pub fn set_peer(
        &mut self,
        id: UdpSocketId,
        peer: Option<UdpEndpoint>,
    ) -> Result<(), PacketError> {
        let binding = self
            .bindings
            .iter_mut()
            .find(|b| b.id == id)
            .ok_or(PacketError::Mismatch)?;
        binding.peer = peer;
        Ok(())
    }

    fn binding(&self, id: UdpSocketId) -> Result<&UdpBinding, PacketError> {
        self.bindings
            .iter()
            .find(|b| b.id == id)
            .ok_or(PacketError::Mismatch)
    }

    pub fn unbind_endpoint(&mut self, id: UdpSocketId) -> bool {
        let Some(index) = self.bindings.iter().position(|b| b.id == id) else {
            return false;
        };
        self.bindings.swap_remove(index);
        true
    }

    fn wildcard_id(&self, port: u16) -> Option<UdpSocketId> {
        self.bindings
            .iter()
            .find(|b| {
                b.local
                    == UdpEndpoint {
                        address: [0; 4],
                        port,
                    }
            })
            .map(|b| b.id)
    }

    pub fn unbind(&mut self, port: u16) -> bool {
        self.wildcard_id(port)
            .is_some_and(|id| self.unbind_endpoint(id))
    }

    pub fn enqueue(
        &mut self,
        source_address: [u8; 4],
        destination_address: [u8; 4],
        datagram: UdpDatagram<'_>,
    ) -> Result<(), PacketError> {
        if datagram.payload.len() > self.payload_limit {
            return Err(PacketError::Capacity);
        }
        let binding = self
            .bindings
            .iter_mut()
            .find(|b| {
                b.local.port == datagram.destination_port
                    && (b.local.address == [0; 4] || b.local.address == destination_address)
            })
            .ok_or(PacketError::Mismatch)?;
        if binding
            .peer
            .is_some_and(|peer| peer.address != source_address || peer.port != datagram.source_port)
        {
            return Err(PacketError::Mismatch);
        }
        if binding.received.len() >= self.queue_limit {
            return Err(PacketError::Capacity);
        }
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(datagram.payload.len())
            .map_err(|_| PacketError::Capacity)?;
        payload.extend_from_slice(datagram.payload);
        binding.received.push_back(UdpPacket {
            source_address,
            destination_address,
            source_port: datagram.source_port,
            destination_port: datagram.destination_port,
            payload,
        });
        Ok(())
    }

    /// An empty live queue is distinct from a stale, already-released identity.
    pub fn receive_for(&mut self, id: UdpSocketId) -> Result<Option<UdpPacket>, PacketError> {
        Ok(self
            .bindings
            .iter_mut()
            .find(|b| b.id == id)
            .ok_or(PacketError::Mismatch)?
            .received
            .pop_front())
    }

    /// Borrow one complete record without consuming it or changing capacity.
    pub fn peek_for(&self, id: UdpSocketId) -> Result<Option<&UdpPacket>, PacketError> {
        Ok(self.binding(id)?.received.front())
    }

    pub fn queued_for(&self, id: UdpSocketId) -> Result<usize, PacketError> {
        Ok(self.binding(id)?.received.len())
    }

    pub fn receive(&mut self, port: u16) -> Option<UdpPacket> {
        let id = self.wildcard_id(port)?;
        self.receive_for(id).ok().flatten()
    }

    pub fn queued(&self, port: u16) -> usize {
        self.wildcard_id(port)
            .and_then(|id| self.queued_for(id).ok())
            .unwrap_or(0)
    }

    fn conflicts(&self, local: UdpEndpoint) -> bool {
        self.bindings
            .iter()
            .any(|binding| binding.local.overlaps(local))
    }

    fn allocate_ephemeral(&mut self, address: [u8; 4]) -> Option<u16> {
        let count = u32::from(EPHEMERAL_PORT_END) - u32::from(EPHEMERAL_PORT_START) + 1;
        for _ in 0..count {
            let candidate = self.next_ephemeral;
            self.next_ephemeral = if candidate == EPHEMERAL_PORT_END {
                EPHEMERAL_PORT_START
            } else {
                candidate + 1
            };
            if !self.conflicts(UdpEndpoint {
                address,
                port: candidate,
            }) {
                return Some(candidate);
            }
        }
        None
    }
}

fn partial(b: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut c = b.chunks_exact(2);
    for p in &mut c {
        sum += u32::from(u16::from_be_bytes([p[0], p[1]]))
    }
    if let Some(&x) = c.remainder().first() {
        sum += u32::from(x) << 8
    }
    sum
}
fn checksum_parts_valid(a: &[u8], b: &[u8]) -> bool {
    let mut sum = partial(a) + partial(b);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16)
    }
    !(sum as u16) == 0
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn udp_checksum_and_length() {
        let d = UdpDatagram {
            source_port: 68,
            destination_port: 67,
            payload: b"hello",
        };
        let mut b = [0; 13];
        d.encode([0; 4], [255; 4], &mut b).unwrap();
        assert_eq!(UdpDatagram::decode([0; 4], [255; 4], &b), Ok(d));
        b[12] ^= 1;
        assert_eq!(
            UdpDatagram::decode([0; 4], [255; 4], &b),
            Err(PacketError::InvalidChecksum)
        );
        d.encode([0; 4], [255; 4], &mut b).unwrap();
        b[4] = 0;
        b[5] = 7;
        assert_eq!(
            UdpDatagram::decode([0; 4], [255; 4], &b),
            Err(PacketError::InvalidLength)
        )
    }

    #[test]
    fn binds_ports_and_allocates_ephemeral_ports() {
        let mut sockets = UdpSocketTable::new(3, 2, 64);
        assert_eq!(sockets.bind(68), Ok(68));
        assert_eq!(sockets.bind(68), Err(PacketError::Mismatch));
        assert_eq!(sockets.bind(0), Ok(EPHEMERAL_PORT_START));
        assert_eq!(sockets.bind(0), Ok(EPHEMERAL_PORT_START + 1));
        assert_eq!(sockets.bind(0), Err(PacketError::Capacity));
        assert!(sockets.unbind(68));
        assert!(!sockets.unbind(68));
    }

    #[test]
    fn receive_queue_and_payload_are_bounded() {
        let mut sockets = UdpSocketTable::new(1, 2, 4);
        assert_eq!(sockets.bind(68), Ok(68));
        let datagram = UdpDatagram {
            source_port: 67,
            destination_port: 68,
            payload: b"abcd",
        };
        assert_eq!(sockets.enqueue([10, 0, 2, 2], [255; 4], datagram), Ok(()));
        assert_eq!(sockets.enqueue([10, 0, 2, 2], [255; 4], datagram), Ok(()));
        assert_eq!(
            sockets.enqueue([10, 0, 2, 2], [255; 4], datagram),
            Err(PacketError::Capacity)
        );
        assert_eq!(sockets.queued(68), 2);
        assert_eq!(
            sockets.receive(68).map(|packet| packet.payload),
            Some(b"abcd".to_vec())
        );
        assert_eq!(sockets.queued(68), 1);
        let oversized = UdpDatagram {
            source_port: 67,
            destination_port: 68,
            payload: b"abcde",
        };
        assert_eq!(
            sockets.enqueue([10, 0, 2, 2], [255; 4], oversized),
            Err(PacketError::Capacity)
        );
    }
}
