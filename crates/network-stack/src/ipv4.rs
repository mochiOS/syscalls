use crate::{PacketError, checksum, checksum_valid};
pub const IPV4_HEADER_LEN: usize = 20;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Header {
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub protocol: u8,
    pub ttl: u8,
    pub identification: u16,
}
impl Ipv4Header {
    pub fn decode(packet: &[u8]) -> Result<(Self, &[u8]), PacketError> {
        if packet.len() < IPV4_HEADER_LEN {
            return Err(PacketError::Truncated);
        }
        if packet[0] != 0x45 {
            return Err(PacketError::InvalidHeader);
        }
        let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        if total < IPV4_HEADER_LEN || total > packet.len() {
            return Err(PacketError::InvalidLength);
        }
        let frag = u16::from_be_bytes([packet[6], packet[7]]);
        if frag & 0x3fff != 0 {
            return Err(PacketError::Unsupported);
        }
        if !checksum_valid(&packet[..IPV4_HEADER_LEN]) {
            return Err(PacketError::InvalidChecksum);
        }
        Ok((
            Self {
                source: packet[12..16]
                    .try_into()
                    .map_err(|_| PacketError::Truncated)?,
                destination: packet[16..20]
                    .try_into()
                    .map_err(|_| PacketError::Truncated)?,
                protocol: packet[9],
                ttl: packet[8],
                identification: u16::from_be_bytes([packet[4], packet[5]]),
            },
            &packet[20..total],
        ))
    }
    pub fn encode(self, payload: &[u8], out: &mut [u8]) -> Result<usize, PacketError> {
        let len = IPV4_HEADER_LEN
            .checked_add(payload.len())
            .ok_or(PacketError::InvalidLength)?;
        let total = u16::try_from(len).map_err(|_| PacketError::InvalidLength)?;
        if out.len() < len {
            return Err(PacketError::Truncated);
        }
        out[..20].fill(0);
        out[0] = 0x45;
        out[2..4].copy_from_slice(&total.to_be_bytes());
        out[4..6].copy_from_slice(&self.identification.to_be_bytes());
        out[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        out[8] = self.ttl;
        out[9] = self.protocol;
        out[12..16].copy_from_slice(&self.source);
        out[16..20].copy_from_slice(&self.destination);
        let sum = checksum(&out[..20]);
        out[10..12].copy_from_slice(&sum.to_be_bytes());
        out[20..len].copy_from_slice(payload);
        Ok(len)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checksum_roundtrip() {
        let h = Ipv4Header {
            source: [10, 0, 2, 15],
            destination: [10, 0, 2, 2],
            protocol: 1,
            ttl: 64,
            identification: 7,
        };
        let mut b = [0; 24];
        h.encode(&[1, 2, 3, 4], &mut b).unwrap();
        assert_eq!(Ipv4Header::decode(&b), Ok((h, [1, 2, 3, 4].as_slice())));
        b[10] ^= 1;
        assert!(matches!(
            Ipv4Header::decode(&b),
            Err(PacketError::InvalidChecksum)
        ))
    }
    #[test]
    fn bad_ihl_length_fragment() {
        let mut b = [0; 20];
        let h = Ipv4Header {
            source: [0; 4],
            destination: [0; 4],
            protocol: 1,
            ttl: 1,
            identification: 0,
        };
        h.encode(&[], &mut b).unwrap();
        b[0] = 0x44;
        assert_eq!(Ipv4Header::decode(&b), Err(PacketError::InvalidHeader));
        h.encode(&[], &mut b).unwrap();
        b[6] = 0x20;
        b[10] = 0;
        b[11] = 0;
        let c = checksum(&b);
        b[10..12].copy_from_slice(&c.to_be_bytes());
        assert_eq!(Ipv4Header::decode(&b), Err(PacketError::Unsupported))
    }
}
