//! Authorize a loader-replayed image, not a caller's claim about transformed code.
//! One read-only native RAM transcript accompanies the request; no Provider I/O.
use super::ProtocolError;
/// Versioned prepared-exec request selector.
pub const OPCODE: u32 = 0x4341_4552;
/// Fixed header size; followed by a bounded UTF-8 authorization key.
pub const HEADER: usize = 56;
/// Maximum request size, including the authorization key.
pub const MAX_REQUEST: usize = HEADER + 255;
/// Encode a transcript length and expected reconstructed image digest.
pub fn encode(
    key: &str,
    length: u64,
    digest: &[u8; 32],
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    if key.is_empty() || key.len() > 255 || key.as_bytes().contains(&0) || length == 0 {
        return Err(ProtocolError::InvalidField);
    }
    let n = HEADER + key.len();
    let b = output.get_mut(..n).ok_or(ProtocolError::InvalidLength)?;
    b.fill(0);
    b[..4].copy_from_slice(&OPCODE.to_le_bytes());
    b[4..8].copy_from_slice(&1u32.to_le_bytes());
    b[8..16].copy_from_slice(&length.to_le_bytes());
    b[16..48].copy_from_slice(digest);
    b[48..52].copy_from_slice(&(key.len() as u32).to_le_bytes());
    b[HEADER..].copy_from_slice(key.as_bytes());
    Ok(n)
}
/// Decode strict lengths/reserved fields; attached RAM rights are checked by policy.
pub fn decode(b: &[u8]) -> Result<(&str, u64, &[u8; 32]), ProtocolError> {
    if b.len() < HEADER || b.len() > MAX_REQUEST {
        return Err(ProtocolError::InvalidLength);
    }
    if u32::from_le_bytes(b[..4].try_into().unwrap()) != OPCODE {
        return Err(ProtocolError::UnknownOpcode);
    }
    if b[4..8] != 1u32.to_le_bytes() {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let length = u64::from_le_bytes(b[8..16].try_into().unwrap());
    let n = u32::from_le_bytes(b[48..52].try_into().unwrap()) as usize;
    if length == 0
        || n == 0
        || n > 255
        || b.len() != HEADER + n
        || b[52..HEADER] != [0; 4]
        || b[HEADER..].contains(&0)
    {
        return Err(ProtocolError::InvalidField);
    }
    let key = core::str::from_utf8(&b[HEADER..]).map_err(|_| ProtocolError::InvalidField)?;
    Ok((key, length, b[16..48].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_header_and_key_roundtrip_rejects_ambiguous_requests() {
        let mut bytes = [0; MAX_REQUEST];
        let digest = [7; 32];
        let n = encode("execve", 128, &digest, &mut bytes).unwrap();
        assert_eq!(decode(&bytes[..n]), Ok(("execve", 128, &digest)));
        for at in [4, 52, 55] {
            let mut bad = bytes;
            bad[at] ^= 1;
            assert!(decode(&bad[..n]).is_err());
        }
        assert!(decode(&bytes[..n - 1]).is_err());
        assert!(decode(&bytes[..n + 1]).is_err());
        assert!(encode("", 1, &digest, &mut bytes).is_err());
        assert!(encode("a\0b", 1, &digest, &mut bytes).is_err());
        assert!(encode("execve", 0, &digest, &mut bytes).is_err());
    }
}
