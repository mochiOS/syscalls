//! Whole-file advisory locking of the exact retained open description.
//! Delivered through CONTROL authority by the native provider transport.
//! No path, descriptor, process ID or caller-selected object ID is accepted.

/// Four little-endian bytes: SHARED, EXCLUSIVE, or UNLOCK. Returns no bytes.
/// Conflicting acquisitions return Linux EAGAIN (11); wait policy is client-side.
pub const UPDATE: u64 = u64::from_le_bytes(*b"MFS1LOCK");
pub const SHARED: u32 = 1;
pub const EXCLUSIVE: u32 = 2;
pub const UNLOCK: u32 = 8;

/// Decode only a complete, unambiguous provider operation.
pub fn decode(bytes: &[u8]) -> Option<u32> {
    let mode = u32::from_le_bytes(bytes.try_into().ok()?);
    matches!(mode, SHARED | EXCLUSIVE | UNLOCK).then_some(mode)
}
