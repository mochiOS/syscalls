//! Exclusive owner-side storage reservation. The returned native Handle is
//! authority to revalidate a reservation, never permission for raw block I/O.
pub const MAGIC: [u8; 8] = *b"MFS1RSRV";
pub const REQUEST_LEN: usize = 32;
pub const RESPONSE_LEN: usize = 8;
pub const VALIDATE: u64 = u64::from_le_bytes(*b"MFS1RVAL");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    /// An observation from the owner's current inventory, not authority.
    pub generation: u64,
    pub disk: u64,
}
impl Request {
    pub fn encode(self) -> [u8; REQUEST_LEN] {
        let mut out = [0; REQUEST_LEN];
        out[..8].copy_from_slice(&MAGIC);
        out[8..16].copy_from_slice(&self.generation.to_le_bytes());
        out[16..24].copy_from_slice(&self.disk.to_le_bytes());
        out
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; REQUEST_LEN] = bytes.try_into().ok()?;
        if bytes[..8] != MAGIC || bytes[24..] != [0; 8] {
            return None;
        }
        let request = Self {
            generation: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            disk: u64::from_le_bytes(bytes[16..24].try_into().ok()?),
        };
        (request.generation != 0 && request.disk != 0).then_some(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_reservation_request_contains_no_caller_or_permission_claim() {
        let request = Request {
            generation: 2,
            disk: 9,
        };
        let bytes = request.encode();
        assert_eq!(Request::decode(&bytes), Some(request));
        assert!(Request::decode(&bytes[..31]).is_none());
        for offset in [0, 24, 31] {
            let mut malformed = bytes;
            malformed[offset] ^= 1;
            assert!(Request::decode(&malformed).is_none());
        }
        assert!(
            Request::decode(
                &Request {
                    generation: 0,
                    ..request
                }
                .encode()
            )
            .is_none()
        );
        assert!(Request::decode(&Request { disk: 0, ..request }.encode()).is_none());
    }
}
