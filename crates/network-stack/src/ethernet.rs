use crate::PacketError;

pub const ETHERNET_HEADER_LEN: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthernetHeader {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ethertype: u16,
}

impl EthernetHeader {
    pub fn decode(frame: &[u8]) -> Result<(Self, &[u8]), PacketError> {
        if frame.len() < ETHERNET_HEADER_LEN {
            return Err(PacketError::Truncated);
        }
        let header = Self {
            destination: frame[0..6].try_into().map_err(|_| PacketError::Truncated)?,
            source: frame[6..12]
                .try_into()
                .map_err(|_| PacketError::Truncated)?,
            ethertype: u16::from_be_bytes([frame[12], frame[13]]),
        };
        if !valid_unicast_mac(header.source) {
            return Err(PacketError::InvalidHeader);
        }
        Ok((header, &frame[14..]))
    }
    pub fn encode(self, payload: &[u8], out: &mut [u8]) -> Result<usize, PacketError> {
        let len = ETHERNET_HEADER_LEN
            .checked_add(payload.len())
            .ok_or(PacketError::InvalidLength)?;
        if out.len() < len {
            return Err(PacketError::Truncated);
        }
        out[0..6].copy_from_slice(&self.destination);
        out[6..12].copy_from_slice(&self.source);
        out[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
        out[14..len].copy_from_slice(payload);
        Ok(len)
    }
    pub fn accepted_for(self, mac: [u8; 6]) -> bool {
        self.destination == mac || self.destination == BROADCAST_MAC
    }
}

pub fn valid_unicast_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac != BROADCAST_MAC && mac[0] & 1 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn golden_roundtrip() {
        let h = EthernetHeader {
            destination: [1, 2, 3, 4, 5, 6],
            source: [8, 8, 9, 10, 11, 12],
            ethertype: ETHERTYPE_IPV4,
        };
        let mut b = [0; 16];
        assert_eq!(h.encode(&[13, 14], &mut b), Ok(16));
        assert_eq!(EthernetHeader::decode(&b), Ok((h, [13, 14].as_slice())))
    }
    #[test]
    fn short_rejected() {
        assert_eq!(
            EthernetHeader::decode(&[0; 13]),
            Err(PacketError::Truncated)
        );
        let mut frame = [0; ETHERNET_HEADER_LEN];
        frame[..6].copy_from_slice(&BROADCAST_MAC);
        frame[6..12].copy_from_slice(&BROADCAST_MAC);
        assert_eq!(
            EthernetHeader::decode(&frame),
            Err(PacketError::InvalidHeader)
        );
    }
}
