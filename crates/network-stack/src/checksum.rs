pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([pair[0], pair[1]])));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum = sum.wrapping_add(u32::from(last) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn checksum_valid(bytes: &[u8]) -> bool {
    checksum(bytes) == 0
}
