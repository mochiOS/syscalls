//! C network byte order helpers. Pure value conversion needs no service call.
#[unsafe(no_mangle)]
pub extern "C" fn htons(value: u16) -> u16 {
    value.to_be()
}
#[unsafe(no_mangle)]
pub extern "C" fn htonl(value: u32) -> u32 {
    value.to_be()
}
#[unsafe(no_mangle)]
pub extern "C" fn ntohs(value: u16) -> u16 {
    u16::from_be(value)
}
#[unsafe(no_mangle)]
pub extern "C" fn ntohl(value: u32) -> u32 {
    u32::from_be(value)
}
