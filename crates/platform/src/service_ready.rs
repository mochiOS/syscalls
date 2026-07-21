pub const MESSAGE_LEN: usize = 12;

const MAGIC: u32 = 0x5952_4453;
const VERSION: u16 = 1;
const KIND_QUERY: u16 = 1;
const KIND_RESULT: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    InvalidKind,
}

fn encode(kind: u16, status: i32) -> [u8; MESSAGE_LEN] {
    let mut message = [0u8; MESSAGE_LEN];
    message[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    message[4..6].copy_from_slice(&VERSION.to_le_bytes());
    message[6..8].copy_from_slice(&kind.to_le_bytes());
    message[8..12].copy_from_slice(&status.to_le_bytes());
    message
}

fn decode(message: &[u8], expected_kind: u16) -> Result<i32, DecodeError> {
    if message.len() != MESSAGE_LEN {
        return Err(DecodeError::InvalidLength);
    }
    let magic = u32::from_le_bytes([message[0], message[1], message[2], message[3]]);
    if magic != MAGIC {
        return Err(DecodeError::InvalidMagic);
    }
    let version = u16::from_le_bytes([message[4], message[5]]);
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion);
    }
    let kind = u16::from_le_bytes([message[6], message[7]]);
    if kind != expected_kind {
        return Err(DecodeError::InvalidKind);
    }
    Ok(i32::from_le_bytes([
        message[8],
        message[9],
        message[10],
        message[11],
    ]))
}

pub fn query() -> [u8; MESSAGE_LEN] {
    encode(KIND_QUERY, 0)
}

pub fn is_query(message: &[u8]) -> bool {
    decode(message, KIND_QUERY) == Ok(0)
}

pub fn result(status: i32) -> [u8; MESSAGE_LEN] {
    encode(KIND_RESULT, status)
}

pub fn decode_result(message: &[u8]) -> Result<i32, DecodeError> {
    decode(message, KIND_RESULT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_has_stable_encoding() {
        assert_eq!(
            query(),
            [0x53, 0x44, 0x52, 0x59, 1, 0, 1, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn result_round_trips_success_and_failure() {
        assert_eq!(decode_result(&result(0)), Ok(0));
        assert_eq!(decode_result(&result(-5)), Ok(-5));
    }

    #[test]
    fn rejects_short_and_unaligned_messages() {
        assert_eq!(decode_result(&result(0)[..MESSAGE_LEN - 1]), Err(DecodeError::InvalidLength));

        let mut storage = [0u8; MESSAGE_LEN + 1];
        storage[1..].copy_from_slice(&result(0));
        assert_eq!(decode_result(&storage[1..]), Ok(0));
    }

    #[test]
    fn rejects_invalid_header_and_kind() {
        let mut invalid_magic = result(0);
        invalid_magic[0] ^= 0xff;
        assert_eq!(decode_result(&invalid_magic), Err(DecodeError::InvalidMagic));

        let mut invalid_version = result(0);
        invalid_version[4] = 2;
        assert_eq!(decode_result(&invalid_version), Err(DecodeError::UnsupportedVersion));

        assert_eq!(decode_result(&query()), Err(DecodeError::InvalidKind));
    }
}
