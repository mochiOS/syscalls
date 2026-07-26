use crate::PacketError;
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
        b[4] = 0;
        b[5] = 7;
        assert_eq!(
            UdpDatagram::decode([0; 4], [255; 4], &b),
            Err(PacketError::InvalidLength)
        )
    }
}
