use crate::{PacketError, checksum, checksum_valid};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EchoPacket<'a> {
    pub reply: bool,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: &'a [u8],
}
impl<'a> EchoPacket<'a> {
    pub fn decode(b: &'a [u8]) -> Result<Self, PacketError> {
        if b.len() < 8 {
            return Err(PacketError::Truncated);
        }
        if b[0] != 0 && b[0] != 8 || b[1] != 0 {
            return Err(PacketError::Unsupported);
        }
        if !checksum_valid(b) {
            return Err(PacketError::InvalidChecksum);
        }
        Ok(Self {
            reply: b[0] == 0,
            identifier: u16::from_be_bytes([b[4], b[5]]),
            sequence: u16::from_be_bytes([b[6], b[7]]),
            payload: &b[8..],
        })
    }
    pub fn encode(self, out: &mut [u8]) -> Result<usize, PacketError> {
        let len = 8usize
            .checked_add(self.payload.len())
            .ok_or(PacketError::InvalidLength)?;
        if out.len() < len {
            return Err(PacketError::Truncated);
        }
        out[..8].fill(0);
        out[0] = if self.reply { 0 } else { 8 };
        out[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        out[6..8].copy_from_slice(&self.sequence.to_be_bytes());
        out[8..len].copy_from_slice(self.payload);
        let c = checksum(&out[..len]);
        out[2..4].copy_from_slice(&c.to_be_bytes());
        Ok(len)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn echo_roundtrip() {
        let p = EchoPacket {
            reply: false,
            identifier: 2,
            sequence: 3,
            payload: b"ping",
        };
        let mut b = [0; 12];
        p.encode(&mut b).unwrap();
        assert_eq!(EchoPacket::decode(&b), Ok(p));
        let reply = EchoPacket { reply: true, ..p };
        reply.encode(&mut b).unwrap();
        assert_eq!(EchoPacket::decode(&b), Ok(reply));
        b[3] ^= 1;
        assert_eq!(EchoPacket::decode(&b), Err(PacketError::InvalidChecksum))
    }
}
