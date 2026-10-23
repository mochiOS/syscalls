//! Provider-owned open-description flags, transported by native Handle calls.
//! The kernel treats these selectors and bytes as opaque.

/// READ-authorized query, or CONTROL-authorized observation for write-only
/// descriptions. Empty input, exactly four output bytes in little endian.
pub const GET: u64 = u64::from_le_bytes(*b"MFS1FLAG");
/// CONTROL-authorized atomic masked update. Eight input bytes: mask then value,
/// both little-endian u32. No output, no cursor change or descriptor-local flags.
pub const UPDATE: u64 = u64::from_le_bytes(*b"MFS1UFLG");

pub fn encode_update(mask: u32, flags: u32) -> Option<[u8; 8]> {
    if mask & !crate::OPEN_STATUS_FLAGS_ALL != 0 || flags & !mask != 0 {
        return None;
    }
    let mut bytes = [0; 8];
    bytes[..4].copy_from_slice(&mask.to_le_bytes());
    bytes[4..].copy_from_slice(&flags.to_le_bytes());
    Some(bytes)
}

pub fn decode_update(bytes: &[u8]) -> Option<(u32, u32)> {
    let bytes: &[u8; 8] = bytes.try_into().ok()?;
    let mask = u32::from_le_bytes(bytes[..4].try_into().ok()?);
    let flags = u32::from_le_bytes(bytes[4..].try_into().ok()?);
    encode_update(mask, flags)?;
    Some((mask, flags))
}
