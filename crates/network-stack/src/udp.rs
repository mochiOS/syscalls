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

struct UdpBinding {
    port: u16,
    received: VecDeque<UdpPacket>,
}

pub struct UdpSocketTable {
    bindings: Vec<UdpBinding>,
    socket_limit: usize,
    queue_limit: usize,
    payload_limit: usize,
    next_ephemeral: u16,
}

impl UdpSocketTable {
    pub fn new(socket_limit: usize, queue_limit: usize, payload_limit: usize) -> Self {
        Self {
            bindings: Vec::with_capacity(socket_limit),
            socket_limit,
            queue_limit,
            payload_limit,
            next_ephemeral: EPHEMERAL_PORT_START,
        }
    }

    pub fn bind(&mut self, requested_port: u16) -> Result<u16, PacketError> {
        if self.bindings.len() >= self.socket_limit {
            return Err(PacketError::Capacity);
        }
        let port = if requested_port == 0 {
            self.allocate_ephemeral().ok_or(PacketError::Capacity)?
        } else {
            if self.is_bound(requested_port) {
                return Err(PacketError::Mismatch);
            }
            requested_port
        };
        self.bindings.push(UdpBinding {
            port,
            received: VecDeque::with_capacity(self.queue_limit),
        });
        Ok(port)
    }

    pub fn unbind(&mut self, port: u16) -> bool {
        let Some(index) = self
            .bindings
            .iter()
            .position(|binding| binding.port == port)
        else {
            return false;
        };
        self.bindings.remove(index);
        true
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
            .find(|binding| binding.port == datagram.destination_port)
            .ok_or(PacketError::Mismatch)?;
        if binding.received.len() >= self.queue_limit {
            return Err(PacketError::Capacity);
        }
        binding.received.push_back(UdpPacket {
            source_address,
            destination_address,
            source_port: datagram.source_port,
            destination_port: datagram.destination_port,
            payload: datagram.payload.to_vec(),
        });
        Ok(())
    }

    pub fn receive(&mut self, port: u16) -> Option<UdpPacket> {
        self.bindings
            .iter_mut()
            .find(|binding| binding.port == port)
            .and_then(|binding| binding.received.pop_front())
    }

    pub fn queued(&self, port: u16) -> usize {
        self.bindings
            .iter()
            .find(|binding| binding.port == port)
            .map_or(0, |binding| binding.received.len())
    }

    fn is_bound(&self, port: u16) -> bool {
        self.bindings.iter().any(|binding| binding.port == port)
    }

    fn allocate_ephemeral(&mut self) -> Option<u16> {
        let count = u32::from(EPHEMERAL_PORT_END) - u32::from(EPHEMERAL_PORT_START) + 1;
        for _ in 0..count {
            let candidate = self.next_ephemeral;
            self.next_ephemeral = if candidate == EPHEMERAL_PORT_END {
                EPHEMERAL_PORT_START
            } else {
                candidate + 1
            };
            if !self.is_bound(candidate) {
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
