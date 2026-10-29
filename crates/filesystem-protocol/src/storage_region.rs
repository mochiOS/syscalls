//! Bounded writable device region; admitted only by privileged owner policy.
pub const MAGIC: [u8; 8] = *b"MFS1RGNW";
pub const FLUSH: u64 = u64::from_le_bytes(*b"MFS1RGSY");
pub const EPOCH: u64 = u64::from_le_bytes(*b"MFS1DEPO");
pub const REQUEST_LEN: usize = 48;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub generation: u64,
    pub disk: u64,
    pub first: u64,
    pub sectors: u64,
    pub epoch: u64,
}
impl Request {
    pub fn encode(self) -> [u8; REQUEST_LEN] {
        let mut b = [0; REQUEST_LEN];
        b[..8].copy_from_slice(&MAGIC);
        for (i, n) in [
            self.generation,
            self.disk,
            self.first,
            self.sectors,
            self.epoch,
        ]
        .iter()
        .enumerate()
        {
            b[8 + i * 8..16 + i * 8].copy_from_slice(&n.to_le_bytes());
        }
        b
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != REQUEST_LEN || b[..8] != MAGIC {
            return None;
        }
        let n = |i| Some(u64::from_le_bytes(b.get(i..i + 8)?.try_into().ok()?));
        let r = Self {
            generation: n(8)?,
            disk: n(16)?,
            first: n(24)?,
            sectors: n(32)?,
            epoch: n(40)?,
        };
        (r.generation != 0
            && r.disk != 0
            && r.epoch != 0
            && r.sectors != 0
            && r.first.checked_add(r.sectors).is_some())
        .then_some(r)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_bounded_request() {
        let r = Request {
            generation: 1,
            disk: 2,
            first: 0,
            sectors: 100,
            epoch: 7,
        };
        assert_eq!(Request::decode(&r.encode()), Some(r));
        for index in [0] {
            let mut b = r.encode();
            b[index] ^= 1;
            assert!(Request::decode(&b).is_none());
        }
        assert!(Request::decode(&r.encode()[..47]).is_none());
        assert!(Request::decode(&Request { epoch: 0, ..r }.encode()).is_none());
        assert!(
            Request::decode(
                &Request {
                    first: u64::MAX,
                    ..r
                }
                .encode()
            )
            .is_none()
        );
        assert!(Request::decode(&Request { sectors: 0, ..r }.encode()).is_none());
    }
}
