use crate::PacketError;
use alloc::collections::VecDeque;

pub const ARP_LEN: usize = 28;
pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpPacket {
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: [u8; 4],
    pub target_mac: [u8; 6],
    pub target_ip: [u8; 4],
}
impl ArpPacket {
    pub fn decode(b: &[u8]) -> Result<Self, PacketError> {
        if b.len() < ARP_LEN {
            return Err(PacketError::Truncated);
        }
        if u16::from_be_bytes([b[0], b[1]]) != 1
            || u16::from_be_bytes([b[2], b[3]]) != 0x0800
            || b[4] != 6
            || b[5] != 4
        {
            return Err(PacketError::InvalidHeader);
        }
        let op = u16::from_be_bytes([b[6], b[7]]);
        if op != ARP_REQUEST && op != ARP_REPLY {
            return Err(PacketError::Unsupported);
        }
        Ok(Self {
            operation: op,
            sender_mac: b[8..14].try_into().map_err(|_| PacketError::Truncated)?,
            sender_ip: b[14..18].try_into().map_err(|_| PacketError::Truncated)?,
            target_mac: b[18..24].try_into().map_err(|_| PacketError::Truncated)?,
            target_ip: b[24..28].try_into().map_err(|_| PacketError::Truncated)?,
        })
    }
    pub fn encode(self, out: &mut [u8]) -> Result<usize, PacketError> {
        if out.len() < ARP_LEN {
            return Err(PacketError::Truncated);
        }
        out[..ARP_LEN].fill(0);
        out[0..2].copy_from_slice(&1u16.to_be_bytes());
        out[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
        out[4] = 6;
        out[5] = 4;
        out[6..8].copy_from_slice(&self.operation.to_be_bytes());
        out[8..14].copy_from_slice(&self.sender_mac);
        out[14..18].copy_from_slice(&self.sender_ip);
        out[18..24].copy_from_slice(&self.target_mac);
        out[24..28].copy_from_slice(&self.target_ip);
        Ok(ARP_LEN)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpEntry {
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub expires_at: u64,
}
pub struct ArpCache {
    entries: VecDeque<ArpEntry>,
    capacity: usize,
}
impl ArpCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            capacity,
        }
    }
    pub fn insert(&mut self, entry: ArpEntry) {
        self.entries.retain(|e| e.ip != entry.ip);
        while self.entries.len() >= self.capacity && self.entries.pop_front().is_some() {}
        if self.capacity != 0 {
            self.entries.push_back(entry)
        }
    }
    pub fn lookup(&mut self, ip: [u8; 4], now: u64) -> Option<[u8; 6]> {
        self.entries.retain(|e| e.expires_at > now);
        self.entries.iter().find(|e| e.ip == ip).map(|e| e.mac)
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packets_and_validation() {
        let p = ArpPacket {
            operation: ARP_REQUEST,
            sender_mac: [1; 6],
            sender_ip: [10, 0, 2, 15],
            target_mac: [0; 6],
            target_ip: [10, 0, 2, 2],
        };
        let mut b = [0; ARP_LEN];
        p.encode(&mut b).unwrap();
        assert_eq!(ArpPacket::decode(&b), Ok(p));
        b[4] = 5;
        assert_eq!(ArpPacket::decode(&b), Err(PacketError::InvalidHeader))
    }
    #[test]
    fn cache_expires_and_is_bounded() {
        let mut c = ArpCache::new(1);
        c.insert(ArpEntry {
            ip: [1; 4],
            mac: [2; 6],
            expires_at: 10,
        });
        assert_eq!(c.lookup([1; 4], 9), Some([2; 6]));
        assert_eq!(c.lookup([1; 4], 10), None);
        c.insert(ArpEntry {
            ip: [1; 4],
            mac: [2; 6],
            expires_at: 20,
        });
        c.insert(ArpEntry {
            ip: [3; 4],
            mac: [4; 6],
            expires_at: 20,
        });
        assert_eq!(c.len(), 1)
    }
}
