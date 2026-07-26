#![no_std]

use core::fmt;

pub const MAGIC: u32 = 0x5445_4e4d;
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 24;
pub const MAX_FRAME_LEN: usize = 1514;
pub const INTERFACE_INFO_LEN: usize = 64;
pub const STATISTICS_LEN: usize = 88;
pub const STATUS_LEN: usize = 32;
pub const PING_REQUEST_LEN: usize = 32;
pub const PING_RESULT_LEN: usize = 40;
pub const STACK_STATISTICS_LEN: usize = 144;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    GetInterfaceInfo = 0x0001,
    TransmitFrame = 0x0002,
    ReceiveFrame = 0x0003,
    GetStatistics = 0x0004,
    InterfaceInfo = 0x8001,
    TransmitComplete = 0x8002,
    FrameReceived = 0x8003,
    Statistics = 0x8004,
    Ping = 0x0101,
    GetStackStatistics = 0x0102,
    PingResult = 0x8101,
    StackStatistics = 0x8102,
}

impl Opcode {
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    pub const fn from_wire(value: u16) -> Option<Self> {
        Some(match value {
            0x0001 => Self::GetInterfaceInfo,
            0x0002 => Self::TransmitFrame,
            0x0003 => Self::ReceiveFrame,
            0x0004 => Self::GetStatistics,
            0x8001 => Self::InterfaceInfo,
            0x8002 => Self::TransmitComplete,
            0x8003 => Self::FrameReceived,
            0x8004 => Self::Statistics,
            0x0101 => Self::Ping,
            0x0102 => Self::GetStackStatistics,
            0x8101 => Self::PingResult,
            0x8102 => Self::StackStatistics,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    BufferTooSmall { required: usize, actual: usize },
    InvalidLength { declared: usize, actual: usize },
    InvalidMagic(u32),
    UnsupportedVersion(u16),
    UnknownOpcode(u16),
    UnexpectedOpcode { expected: Opcode, actual: Opcode },
    NonZeroReserved(u32),
    FrameTooLarge(usize),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub opcode: Opcode,
    pub request_id: u64,
    pub length: usize,
}

impl Header {
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() < HEADER_LEN {
            return Err(WireError::InvalidLength {
                declared: HEADER_LEN,
                actual: bytes.len(),
            });
        }
        let magic = read_u32(bytes, 0);
        if magic != MAGIC {
            return Err(WireError::InvalidMagic(magic));
        }
        let version = read_u16(bytes, 4);
        if version != VERSION {
            return Err(WireError::UnsupportedVersion(version));
        }
        let raw_opcode = read_u16(bytes, 6);
        let opcode = Opcode::from_wire(raw_opcode).ok_or(WireError::UnknownOpcode(raw_opcode))?;
        let length = read_u32(bytes, 8) as usize;
        if length != bytes.len() || length < HEADER_LEN {
            return Err(WireError::InvalidLength {
                declared: length,
                actual: bytes.len(),
            });
        }
        let reserved = read_u32(bytes, 12);
        if reserved != 0 {
            return Err(WireError::NonZeroReserved(reserved));
        }
        Ok(Self {
            opcode,
            request_id: read_u64(bytes, 16),
            length,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceInfo {
    pub interface_id: u64,
    pub mac: [u8; 6],
    pub link_up: bool,
    pub mtu: u16,
    pub driver_id: u32,
    pub device_id: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceStatistics {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_dropped: u64,
    pub rx_errors: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_dropped: u64,
    pub tx_errors: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StackStatistics {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub rx_dropped: u64,
    pub rx_errors: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_dropped: u64,
    pub tx_errors: u64,
    pub arp_requests: u64,
    pub arp_cache_hits: u64,
    pub arp_cache_misses: u64,
    pub ipv4_checksum_errors: u64,
    pub icmp_echo_requests: u64,
    pub icmp_echo_replies: u64,
    pub dhcp_attempts: u64,
}

pub fn encode_empty(opcode: Opcode, request_id: u64, out: &mut [u8]) -> Result<usize, WireError> {
    write_header(opcode, request_id, HEADER_LEN, out)?;
    Ok(HEADER_LEN)
}

pub fn decode_empty(expected: Opcode, bytes: &[u8]) -> Result<u64, WireError> {
    let header = Header::decode(bytes)?;
    expect_opcode(header.opcode, expected)?;
    if header.length != HEADER_LEN {
        return Err(WireError::InvalidLength {
            declared: HEADER_LEN,
            actual: header.length,
        });
    }
    Ok(header.request_id)
}

pub fn encode_frame(
    opcode: Opcode,
    request_id: u64,
    frame: &[u8],
    out: &mut [u8],
) -> Result<usize, WireError> {
    if frame.len() > MAX_FRAME_LEN {
        return Err(WireError::FrameTooLarge(frame.len()));
    }
    let length = HEADER_LEN
        .checked_add(4)
        .and_then(|n| n.checked_add(frame.len()))
        .ok_or(WireError::FrameTooLarge(frame.len()))?;
    write_header(opcode, request_id, length, out)?;
    write_u32(out, HEADER_LEN, frame.len() as u32);
    out[HEADER_LEN + 4..length].copy_from_slice(frame);
    Ok(length)
}

pub fn decode_frame(expected: Opcode, bytes: &[u8]) -> Result<(u64, &[u8]), WireError> {
    let header = Header::decode(bytes)?;
    expect_opcode(header.opcode, expected)?;
    if bytes.len() < HEADER_LEN + 4 {
        return Err(WireError::InvalidLength {
            declared: HEADER_LEN + 4,
            actual: bytes.len(),
        });
    }
    let frame_len = read_u32(bytes, HEADER_LEN) as usize;
    if frame_len > MAX_FRAME_LEN {
        return Err(WireError::FrameTooLarge(frame_len));
    }
    let expected_len = HEADER_LEN + 4 + frame_len;
    if bytes.len() != expected_len {
        return Err(WireError::InvalidLength {
            declared: expected_len,
            actual: bytes.len(),
        });
    }
    Ok((header.request_id, &bytes[HEADER_LEN + 4..]))
}

pub fn encode_status(
    opcode: Opcode,
    request_id: u64,
    status: i32,
    out: &mut [u8],
) -> Result<usize, WireError> {
    write_header(opcode, request_id, STATUS_LEN, out)?;
    write_i32(out, 24, status);
    write_u32(out, 28, 0);
    Ok(STATUS_LEN)
}

pub fn decode_status(expected: Opcode, bytes: &[u8]) -> Result<(u64, i32), WireError> {
    let header = Header::decode(bytes)?;
    expect_opcode(header.opcode, expected)?;
    if bytes.len() != STATUS_LEN {
        return Err(WireError::InvalidLength {
            declared: STATUS_LEN,
            actual: bytes.len(),
        });
    }
    let reserved = read_u32(bytes, 28);
    if reserved != 0 {
        return Err(WireError::NonZeroReserved(reserved));
    }
    Ok((header.request_id, read_i32(bytes, 24)))
}

pub fn encode_interface_info(
    request_id: u64,
    info: InterfaceInfo,
    out: &mut [u8],
) -> Result<usize, WireError> {
    write_header(Opcode::InterfaceInfo, request_id, INTERFACE_INFO_LEN, out)?;
    write_u64(out, 24, info.interface_id);
    out[32..38].copy_from_slice(&info.mac);
    out[38] = u8::from(info.link_up);
    out[39] = 0;
    write_u16(out, 40, info.mtu);
    write_u16(out, 42, 0);
    write_u32(out, 44, info.driver_id);
    write_u32(out, 48, info.device_id);
    out[52..64].fill(0);
    Ok(INTERFACE_INFO_LEN)
}

pub fn decode_interface_info(bytes: &[u8]) -> Result<(u64, InterfaceInfo), WireError> {
    let header = Header::decode(bytes)?;
    expect_opcode(header.opcode, Opcode::InterfaceInfo)?;
    if bytes.len() != INTERFACE_INFO_LEN {
        return Err(WireError::InvalidLength {
            declared: INTERFACE_INFO_LEN,
            actual: bytes.len(),
        });
    }
    if bytes[39] != 0 || read_u16(bytes, 42) != 0 || bytes[52..64].iter().any(|b| *b != 0) {
        return Err(WireError::NonZeroReserved(1));
    }
    Ok((
        header.request_id,
        InterfaceInfo {
            interface_id: read_u64(bytes, 24),
            mac: [
                bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37],
            ],
            link_up: bytes[38] != 0,
            mtu: read_u16(bytes, 40),
            driver_id: read_u32(bytes, 44),
            device_id: read_u32(bytes, 48),
        },
    ))
}

pub fn encode_statistics(
    opcode: Opcode,
    request_id: u64,
    stats: DeviceStatistics,
    out: &mut [u8],
) -> Result<usize, WireError> {
    write_header(opcode, request_id, STATISTICS_LEN, out)?;
    for (index, value) in [
        stats.rx_packets,
        stats.rx_bytes,
        stats.rx_dropped,
        stats.rx_errors,
        stats.tx_packets,
        stats.tx_bytes,
        stats.tx_dropped,
        stats.tx_errors,
    ]
    .into_iter()
    .enumerate()
    {
        write_u64(out, 24 + index * 8, value);
    }
    Ok(STATISTICS_LEN)
}

pub fn decode_statistics(
    expected: Opcode,
    bytes: &[u8],
) -> Result<(u64, DeviceStatistics), WireError> {
    let header = Header::decode(bytes)?;
    expect_opcode(header.opcode, expected)?;
    if bytes.len() != STATISTICS_LEN {
        return Err(WireError::InvalidLength {
            declared: STATISTICS_LEN,
            actual: bytes.len(),
        });
    }
    Ok((
        header.request_id,
        DeviceStatistics {
            rx_packets: read_u64(bytes, 24),
            rx_bytes: read_u64(bytes, 32),
            rx_dropped: read_u64(bytes, 40),
            rx_errors: read_u64(bytes, 48),
            tx_packets: read_u64(bytes, 56),
            tx_bytes: read_u64(bytes, 64),
            tx_dropped: read_u64(bytes, 72),
            tx_errors: read_u64(bytes, 80),
        },
    ))
}

pub fn encode_ping(request_id: u64, address: [u8; 4], out: &mut [u8]) -> Result<usize, WireError> {
    write_header(Opcode::Ping, request_id, PING_REQUEST_LEN, out)?;
    out[24..28].copy_from_slice(&address);
    out[28..32].fill(0);
    Ok(PING_REQUEST_LEN)
}

pub fn decode_ping(bytes: &[u8]) -> Result<(u64, [u8; 4]), WireError> {
    let header = Header::decode(bytes)?;
    expect_opcode(header.opcode, Opcode::Ping)?;
    if bytes.len() != PING_REQUEST_LEN {
        return Err(WireError::InvalidLength {
            declared: PING_REQUEST_LEN,
            actual: bytes.len(),
        });
    }
    if bytes[28..32].iter().any(|byte| *byte != 0) {
        return Err(WireError::NonZeroReserved(1));
    }
    Ok((
        header.request_id,
        [bytes[24], bytes[25], bytes[26], bytes[27]],
    ))
}

pub fn encode_ping_result(
    request_id: u64,
    status: i32,
    rtt_ms: u64,
    out: &mut [u8],
) -> Result<usize, WireError> {
    write_header(Opcode::PingResult, request_id, PING_RESULT_LEN, out)?;
    write_i32(out, 24, status);
    write_u32(out, 28, 0);
    write_u64(out, 32, rtt_ms);
    Ok(PING_RESULT_LEN)
}

pub fn decode_ping_result(bytes: &[u8]) -> Result<(u64, i32, u64), WireError> {
    let header = Header::decode(bytes)?;
    expect_opcode(header.opcode, Opcode::PingResult)?;
    if bytes.len() != PING_RESULT_LEN {
        return Err(WireError::InvalidLength {
            declared: PING_RESULT_LEN,
            actual: bytes.len(),
        });
    }
    let reserved = read_u32(bytes, 28);
    if reserved != 0 {
        return Err(WireError::NonZeroReserved(reserved));
    }
    Ok((header.request_id, read_i32(bytes, 24), read_u64(bytes, 32)))
}

pub fn encode_stack_statistics(
    request_id: u64,
    stats: StackStatistics,
    out: &mut [u8],
) -> Result<usize, WireError> {
    write_header(
        Opcode::StackStatistics,
        request_id,
        STACK_STATISTICS_LEN,
        out,
    )?;
    for (index, value) in [
        stats.rx_packets,
        stats.rx_bytes,
        stats.rx_dropped,
        stats.rx_errors,
        stats.tx_packets,
        stats.tx_bytes,
        stats.tx_dropped,
        stats.tx_errors,
        stats.arp_requests,
        stats.arp_cache_hits,
        stats.arp_cache_misses,
        stats.ipv4_checksum_errors,
        stats.icmp_echo_requests,
        stats.icmp_echo_replies,
        stats.dhcp_attempts,
    ]
    .into_iter()
    .enumerate()
    {
        write_u64(out, 24 + index * 8, value)
    }
    Ok(STACK_STATISTICS_LEN)
}

pub fn decode_stack_statistics(bytes: &[u8]) -> Result<(u64, StackStatistics), WireError> {
    let h = Header::decode(bytes)?;
    expect_opcode(h.opcode, Opcode::StackStatistics)?;
    if bytes.len() != STACK_STATISTICS_LEN {
        return Err(WireError::InvalidLength {
            declared: STACK_STATISTICS_LEN,
            actual: bytes.len(),
        });
    }
    Ok((
        h.request_id,
        StackStatistics {
            rx_packets: read_u64(bytes, 24),
            rx_bytes: read_u64(bytes, 32),
            rx_dropped: read_u64(bytes, 40),
            rx_errors: read_u64(bytes, 48),
            tx_packets: read_u64(bytes, 56),
            tx_bytes: read_u64(bytes, 64),
            tx_dropped: read_u64(bytes, 72),
            tx_errors: read_u64(bytes, 80),
            arp_requests: read_u64(bytes, 88),
            arp_cache_hits: read_u64(bytes, 96),
            arp_cache_misses: read_u64(bytes, 104),
            ipv4_checksum_errors: read_u64(bytes, 112),
            icmp_echo_requests: read_u64(bytes, 120),
            icmp_echo_replies: read_u64(bytes, 128),
            dhcp_attempts: read_u64(bytes, 136),
        },
    ))
}

fn expect_opcode(actual: Opcode, expected: Opcode) -> Result<(), WireError> {
    if actual == expected {
        Ok(())
    } else {
        Err(WireError::UnexpectedOpcode { expected, actual })
    }
}

fn write_header(
    opcode: Opcode,
    request_id: u64,
    length: usize,
    out: &mut [u8],
) -> Result<(), WireError> {
    if out.len() < length {
        return Err(WireError::BufferTooSmall {
            required: length,
            actual: out.len(),
        });
    }
    let length_u32 = u32::try_from(length).map_err(|_| WireError::BufferTooSmall {
        required: length,
        actual: out.len(),
    })?;
    write_u32(out, 0, MAGIC);
    write_u16(out, 4, VERSION);
    write_u16(out, 6, opcode.wire_value());
    write_u32(out, 8, length_u32);
    write_u32(out, 12, 0);
    write_u64(out, 16, request_id);
    Ok(())
}

fn read_u16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn read_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn read_i32(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn read_u64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes([
        b[o],
        b[o + 1],
        b[o + 2],
        b[o + 3],
        b[o + 4],
        b[o + 5],
        b[o + 6],
        b[o + 7],
    ])
}
fn write_u16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn write_u32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn write_i32(b: &mut [u8], o: usize, v: i32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn write_u64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn header_is_golden_and_unaligned() {
        let mut storage = [0u8; HEADER_LEN + 1];
        encode_empty(Opcode::GetInterfaceInfo, u64::MAX, &mut storage[1..]).unwrap();
        assert_eq!(
            &storage[1..],
            &[
                0x4d, 0x4e, 0x45, 0x54, 1, 0, 1, 0, 24, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255,
                255, 255, 255, 255
            ]
        );
        assert_eq!(
            decode_empty(Opcode::GetInterfaceInfo, &storage[1..]),
            Ok(u64::MAX)
        );
    }
    #[test]
    fn frame_round_trip_and_limits() {
        let frame = [0xa5; MAX_FRAME_LEN];
        let mut out = [0u8; HEADER_LEN + 4 + MAX_FRAME_LEN];
        let n = encode_frame(Opcode::TransmitFrame, 9, &frame, &mut out).unwrap();
        assert_eq!(
            decode_frame(Opcode::TransmitFrame, &out[..n]),
            Ok((9, frame.as_slice()))
        );
        assert!(matches!(
            encode_frame(Opcode::TransmitFrame, 1, &[0; MAX_FRAME_LEN + 1], &mut out),
            Err(WireError::FrameTooLarge(_))
        ));
    }
    #[test]
    fn validates_header_and_exact_length() {
        let mut b = [0u8; HEADER_LEN];
        encode_empty(Opcode::ReceiveFrame, 1, &mut b).unwrap();
        b[0] = 0;
        assert!(matches!(
            Header::decode(&b),
            Err(WireError::InvalidMagic(_))
        ));
        b[0] = 0x4d;
        b[4] = 2;
        assert!(matches!(
            Header::decode(&b),
            Err(WireError::UnsupportedVersion(2))
        ));
        b[4] = 1;
        b[6] = 0xff;
        b[7] = 0x7f;
        assert!(matches!(
            Header::decode(&b),
            Err(WireError::UnknownOpcode(_))
        ));
        assert!(matches!(
            Header::decode(&b[..20]),
            Err(WireError::InvalidLength { .. })
        ));
    }
    #[test]
    fn status_and_info_validate_reserved_and_buffer() {
        let mut b = [0u8; INTERFACE_INFO_LEN];
        let info = InterfaceInfo {
            interface_id: 1,
            mac: [1, 2, 3, 4, 5, 6],
            link_up: true,
            mtu: 1500,
            driver_id: 7,
            device_id: 8,
        };
        encode_interface_info(3, info, &mut b).unwrap();
        assert_eq!(decode_interface_info(&b), Ok((3, info)));
        b[39] = 1;
        assert!(matches!(
            decode_interface_info(&b),
            Err(WireError::NonZeroReserved(_))
        ));
        assert!(matches!(
            encode_interface_info(1, info, &mut [0; 10]),
            Err(WireError::BufferTooSmall { .. })
        ));
    }
    #[test]
    fn statistics_round_trip() {
        let s = DeviceStatistics {
            rx_packets: 1,
            rx_bytes: 2,
            rx_dropped: 3,
            rx_errors: 4,
            tx_packets: 5,
            tx_bytes: 6,
            tx_dropped: 7,
            tx_errors: 8,
        };
        let mut b = [0; STATISTICS_LEN];
        encode_statistics(Opcode::Statistics, 4, s, &mut b).unwrap();
        assert_eq!(decode_statistics(Opcode::Statistics, &b), Ok((4, s)));
    }
}
