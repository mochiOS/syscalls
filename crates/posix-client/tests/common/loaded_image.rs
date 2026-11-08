pub fn source() -> Vec<u8> {
    let mut bytes = vec![0; 8192];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&4096u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&128u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[128..132].copy_from_slice(&1u32.to_le_bytes());
    bytes[132..136].copy_from_slice(&5u32.to_le_bytes());
    bytes[160..168].copy_from_slice(&8192u64.to_le_bytes());
    bytes[168..176].copy_from_slice(&8192u64.to_le_bytes());
    bytes[176..184].copy_from_slice(&4096u64.to_le_bytes());
    bytes
}
