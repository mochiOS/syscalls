#![no_std]

use core::fmt;

pub const MAGIC: u32 = 0x4356_5244;
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 16;
pub const DRIVER_HELLO_LEN: usize = 32;
pub const START_DISCOVERY_LEN: usize = 32;
pub const DISCOVERY_COMPLETE_LEN: usize = 24;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    DriverHello = 0x0001,
    StartDiscovery = 0x0002,
    DiscoveryComplete = 0x8002,
}

impl Opcode {
    pub const fn wire_value(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    BufferTooSmall { required: usize, actual: usize },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { required, actual } => {
                write!(
                    f,
                    "encode buffer too small: required {required}, actual {actual}"
                )
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    InvalidLength { expected: usize, actual: usize },
    InvalidMagic { actual: u32 },
    UnsupportedVersion { actual: u16 },
    UnknownOpcode { actual: u16 },
    UnexpectedOpcode { expected: Opcode, actual: Opcode },
    NonZeroReserved { actual: u32 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid message length: expected {expected}, actual {actual}"
                )
            }
            Self::InvalidMagic { actual } => write!(f, "invalid magic: {actual:#010x}"),
            Self::UnsupportedVersion { actual } => {
                write!(f, "unsupported protocol version: {actual}")
            }
            Self::UnknownOpcode { actual } => write!(f, "unknown opcode: {actual:#06x}"),
            Self::UnexpectedOpcode { expected, actual } => write!(
                f,
                "unexpected opcode: expected {:#06x}, actual {:#06x}",
                expected.wire_value(),
                actual.wire_value()
            ),
            Self::NonZeroReserved { actual } => {
                write!(f, "reserved field must be zero: {actual:#010x}")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub opcode: Opcode,
    pub request_id: u64,
}

impl Header {
    pub const fn encoded_len(&self) -> usize {
        HEADER_LEN
    }

    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        require_encode_len(buffer, HEADER_LEN)?;
        write_header(buffer, self.opcode, self.request_id);
        Ok(HEADER_LEN)
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, DecodeError> {
        require_decode_len(buffer, HEADER_LEN)?;
        decode_header(buffer)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriverHello {
    pub request_id: u64,
    /// An opaque value. This protocol does not define ownership or lifetime rules.
    pub token: u64,
    /// An opaque endpoint value. This protocol does not own or validate the endpoint.
    pub control_endpoint: u64,
}

impl DriverHello {
    pub const fn opcode(&self) -> Opcode {
        Opcode::DriverHello
    }

    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn encoded_len(&self) -> usize {
        DRIVER_HELLO_LEN
    }

    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        require_encode_len(buffer, DRIVER_HELLO_LEN)?;
        write_header(buffer, self.opcode(), self.request_id);
        write_u64(buffer, 16, self.token);
        write_u64(buffer, 24, self.control_endpoint);
        Ok(DRIVER_HELLO_LEN)
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, DecodeError> {
        require_decode_len(buffer, DRIVER_HELLO_LEN)?;
        let header = decode_expected_header(buffer, Opcode::DriverHello)?;
        Ok(Self {
            request_id: header.request_id,
            token: read_u64(buffer, 16),
            control_endpoint: read_u64(buffer, 24),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartDiscovery {
    pub request_id: u64,
    /// An opaque value. This protocol does not define ownership or lifetime rules.
    pub token: u64,
    /// An opaque endpoint value. This protocol does not own or validate the endpoint.
    pub response_endpoint: u64,
}

impl StartDiscovery {
    pub const fn opcode(&self) -> Opcode {
        Opcode::StartDiscovery
    }

    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn encoded_len(&self) -> usize {
        START_DISCOVERY_LEN
    }

    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        require_encode_len(buffer, START_DISCOVERY_LEN)?;
        write_header(buffer, self.opcode(), self.request_id);
        write_u64(buffer, 16, self.token);
        write_u64(buffer, 24, self.response_endpoint);
        Ok(START_DISCOVERY_LEN)
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, DecodeError> {
        require_decode_len(buffer, START_DISCOVERY_LEN)?;
        let header = decode_expected_header(buffer, Opcode::StartDiscovery)?;
        Ok(Self {
            request_id: header.request_id,
            token: read_u64(buffer, 16),
            response_endpoint: read_u64(buffer, 24),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveryResult {
    /// The discovery-phase result. Zero means that discovery completed, not that every driver
    /// process was spawned successfully. Protocol-level errors such as `EBUSY` are representable.
    pub status: i32,
}

impl DiscoveryResult {
    /// Builds a response for a request, allowing a saved completed result to be returned again.
    pub const fn response(self, request_id: u64) -> DiscoveryComplete {
        DiscoveryComplete {
            request_id,
            status: self.status,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveryComplete {
    pub request_id: u64,
    /// The discovery-phase result. Zero does not imply that every driver spawn succeeded.
    pub status: i32,
}

impl DiscoveryComplete {
    pub const fn opcode(&self) -> Opcode {
        Opcode::DiscoveryComplete
    }

    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn encoded_len(&self) -> usize {
        DISCOVERY_COMPLETE_LEN
    }

    pub const fn result(&self) -> DiscoveryResult {
        DiscoveryResult {
            status: self.status,
        }
    }

    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        require_encode_len(buffer, DISCOVERY_COMPLETE_LEN)?;
        write_header(buffer, self.opcode(), self.request_id);
        write_i32(buffer, 16, self.status);
        write_u32(buffer, 20, 0);
        Ok(DISCOVERY_COMPLETE_LEN)
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, DecodeError> {
        require_decode_len(buffer, DISCOVERY_COMPLETE_LEN)?;
        let header = decode_expected_header(buffer, Opcode::DiscoveryComplete)?;
        let reserved = read_u32(buffer, 20);
        if reserved != 0 {
            return Err(DecodeError::NonZeroReserved { actual: reserved });
        }
        Ok(Self {
            request_id: header.request_id,
            status: read_i32(buffer, 16),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Message {
    DriverHello(DriverHello),
    StartDiscovery(StartDiscovery),
    DiscoveryComplete(DiscoveryComplete),
}

impl Message {
    pub const fn opcode(&self) -> Opcode {
        match self {
            Self::DriverHello(message) => message.opcode(),
            Self::StartDiscovery(message) => message.opcode(),
            Self::DiscoveryComplete(message) => message.opcode(),
        }
    }

    pub const fn request_id(&self) -> u64 {
        match self {
            Self::DriverHello(message) => message.request_id(),
            Self::StartDiscovery(message) => message.request_id(),
            Self::DiscoveryComplete(message) => message.request_id(),
        }
    }

    pub const fn encoded_len(&self) -> usize {
        match self {
            Self::DriverHello(message) => message.encoded_len(),
            Self::StartDiscovery(message) => message.encoded_len(),
            Self::DiscoveryComplete(message) => message.encoded_len(),
        }
    }

    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        match self {
            Self::DriverHello(message) => message.encode(buffer),
            Self::StartDiscovery(message) => message.encode(buffer),
            Self::DiscoveryComplete(message) => message.encode(buffer),
        }
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, DecodeError> {
        if buffer.len() < HEADER_LEN {
            return Err(DecodeError::InvalidLength {
                expected: HEADER_LEN,
                actual: buffer.len(),
            });
        }
        let header = decode_header(buffer)?;
        match header.opcode {
            Opcode::DriverHello => DriverHello::decode(buffer).map(Self::DriverHello),
            Opcode::StartDiscovery => StartDiscovery::decode(buffer).map(Self::StartDiscovery),
            Opcode::DiscoveryComplete => {
                DiscoveryComplete::decode(buffer).map(Self::DiscoveryComplete)
            }
        }
    }
}

fn require_encode_len(buffer: &[u8], required: usize) -> Result<(), EncodeError> {
    if buffer.len() < required {
        return Err(EncodeError::BufferTooSmall {
            required,
            actual: buffer.len(),
        });
    }
    Ok(())
}

fn require_decode_len(buffer: &[u8], expected: usize) -> Result<(), DecodeError> {
    if buffer.len() != expected {
        return Err(DecodeError::InvalidLength {
            expected,
            actual: buffer.len(),
        });
    }
    Ok(())
}

fn decode_expected_header(buffer: &[u8], expected: Opcode) -> Result<Header, DecodeError> {
    let header = decode_header(buffer)?;
    if header.opcode != expected {
        return Err(DecodeError::UnexpectedOpcode {
            expected,
            actual: header.opcode,
        });
    }
    Ok(header)
}

fn decode_header(buffer: &[u8]) -> Result<Header, DecodeError> {
    let magic = read_u32(buffer, 0);
    if magic != MAGIC {
        return Err(DecodeError::InvalidMagic { actual: magic });
    }
    let version = read_u16(buffer, 4);
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion { actual: version });
    }
    let opcode_value = read_u16(buffer, 6);
    let opcode = match opcode_value {
        0x0001 => Opcode::DriverHello,
        0x0002 => Opcode::StartDiscovery,
        0x8002 => Opcode::DiscoveryComplete,
        _ => {
            return Err(DecodeError::UnknownOpcode {
                actual: opcode_value,
            });
        }
    };
    Ok(Header {
        opcode,
        request_id: read_u64(buffer, 8),
    })
}

fn read_u16(buffer: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buffer[offset], buffer[offset + 1]])
}

fn read_u32(buffer: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ])
}

fn read_i32(buffer: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ])
}

fn read_u64(buffer: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
        buffer[offset + 4],
        buffer[offset + 5],
        buffer[offset + 6],
        buffer[offset + 7],
    ])
}

fn write_u16(buffer: &mut [u8], offset: usize, value: u16) {
    buffer[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_i32(buffer: &mut [u8], offset: usize, value: i32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_header(buffer: &mut [u8], opcode: Opcode, request_id: u64) {
    write_u32(buffer, 0, MAGIC);
    write_u16(buffer, 4, VERSION);
    write_u16(buffer, 6, opcode.wire_value());
    write_u64(buffer, 8, request_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(message: Message) -> [u8; DRIVER_HELLO_LEN] {
        let mut buffer = [0u8; DRIVER_HELLO_LEN];
        let length = match message.encode(&mut buffer) {
            Ok(length) => length,
            Err(error) => panic!("encode failed: {error:?}"),
        };
        assert_eq!(length, message.encoded_len());
        buffer
    }

    #[test]
    fn constants_and_opcodes_match_wire_specification() {
        assert_eq!(MAGIC, 0x4356_5244);
        assert_eq!(VERSION, 1);
        assert_eq!(HEADER_LEN, 16);
        assert_eq!(DRIVER_HELLO_LEN, 32);
        assert_eq!(START_DISCOVERY_LEN, 32);
        assert_eq!(DISCOVERY_COMPLETE_LEN, 24);
        assert_eq!(Opcode::DriverHello.wire_value(), 0x0001);
        assert_eq!(Opcode::StartDiscovery.wire_value(), 0x0002);
        assert_eq!(Opcode::DiscoveryComplete.wire_value(), 0x8002);
    }

    #[test]
    fn driver_hello_round_trip_and_golden_bytes() {
        let message = DriverHello {
            request_id: 0x0807_0605_0403_0201,
            token: 0x1817_1615_1413_1211,
            control_endpoint: 0x2827_2625_2423_2221,
        };
        let buffer = encoded(Message::DriverHello(message));
        assert_eq!(
            buffer,
            [
                b'D', b'R', b'V', b'C', 1, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 17, 18, 19, 20, 21, 22,
                23, 24, 33, 34, 35, 36, 37, 38, 39, 40,
            ]
        );
        assert_eq!(DriverHello::decode(&buffer), Ok(message));
        assert_eq!(Message::decode(&buffer), Ok(Message::DriverHello(message)));
    }

    #[test]
    fn start_discovery_round_trip_and_golden_bytes() {
        let message = StartDiscovery {
            request_id: 9,
            token: 10,
            response_endpoint: 11,
        };
        let buffer = encoded(Message::StartDiscovery(message));
        assert_eq!(
            buffer,
            [
                b'D', b'R', b'V', b'C', 1, 0, 2, 0, 9, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0,
                0, 11, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(StartDiscovery::decode(&buffer), Ok(message));
        assert_eq!(
            Message::decode(&buffer),
            Ok(Message::StartDiscovery(message))
        );
    }

    #[test]
    fn discovery_complete_round_trip_and_golden_bytes() {
        let message = DiscoveryComplete {
            request_id: 12,
            status: -16,
        };
        let mut buffer = [0u8; DISCOVERY_COMPLETE_LEN];
        assert_eq!(message.encode(&mut buffer), Ok(DISCOVERY_COMPLETE_LEN));
        assert_eq!(
            buffer,
            [
                b'D', b'R', b'V', b'C', 1, 0, 2, 128, 12, 0, 0, 0, 0, 0, 0, 0, 240, 255, 255, 255,
                0, 0, 0, 0,
            ]
        );
        assert_eq!(DiscoveryComplete::decode(&buffer), Ok(message));
        assert_eq!(
            Message::decode(&buffer),
            Ok(Message::DiscoveryComplete(message))
        );
    }

    #[test]
    fn rejects_magic_version_and_unknown_opcode() {
        let message = DriverHello {
            request_id: 1,
            token: 2,
            control_endpoint: 3,
        };
        let mut buffer = encoded(Message::DriverHello(message));
        buffer[0] = 0;
        assert_eq!(
            Message::decode(&buffer),
            Err(DecodeError::InvalidMagic {
                actual: 0x4356_5200,
            })
        );

        buffer = encoded(Message::DriverHello(message));
        buffer[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            Message::decode(&buffer),
            Err(DecodeError::UnsupportedVersion { actual: 2 })
        );

        buffer = encoded(Message::DriverHello(message));
        buffer[6..8].copy_from_slice(&0x7777u16.to_le_bytes());
        assert_eq!(
            Message::decode(&buffer),
            Err(DecodeError::UnknownOpcode { actual: 0x7777 })
        );
    }

    #[test]
    fn rejects_short_and_trailing_messages_consistently() {
        let hello = DriverHello {
            request_id: 1,
            token: 2,
            control_endpoint: 3,
        };
        let hello_buffer = encoded(Message::DriverHello(hello));
        assert_eq!(
            DriverHello::decode(&hello_buffer[..31]),
            Err(DecodeError::InvalidLength {
                expected: DRIVER_HELLO_LEN,
                actual: 31,
            })
        );
        let mut trailing = [0u8; DRIVER_HELLO_LEN + 1];
        trailing[..DRIVER_HELLO_LEN].copy_from_slice(&hello_buffer);
        assert_eq!(
            Message::decode(&trailing),
            Err(DecodeError::InvalidLength {
                expected: DRIVER_HELLO_LEN,
                actual: DRIVER_HELLO_LEN + 1,
            })
        );
        assert_eq!(
            Message::decode(&hello_buffer[..15]),
            Err(DecodeError::InvalidLength {
                expected: HEADER_LEN,
                actual: 15,
            })
        );

        let start = StartDiscovery {
            request_id: 1,
            token: 2,
            response_endpoint: 3,
        };
        let start_buffer = encoded(Message::StartDiscovery(start));
        assert_eq!(
            StartDiscovery::decode(&start_buffer[..31]),
            Err(DecodeError::InvalidLength {
                expected: START_DISCOVERY_LEN,
                actual: 31,
            })
        );
        let mut trailing_start = [0u8; START_DISCOVERY_LEN + 1];
        trailing_start[..START_DISCOVERY_LEN].copy_from_slice(&start_buffer);
        assert_eq!(
            Message::decode(&trailing_start),
            Err(DecodeError::InvalidLength {
                expected: START_DISCOVERY_LEN,
                actual: START_DISCOVERY_LEN + 1,
            })
        );

        let complete = DiscoveryComplete {
            request_id: 1,
            status: 0,
        };
        let mut complete_buffer = [0u8; DISCOVERY_COMPLETE_LEN];
        assert_eq!(
            complete.encode(&mut complete_buffer),
            Ok(DISCOVERY_COMPLETE_LEN)
        );
        assert_eq!(
            DiscoveryComplete::decode(&complete_buffer[..23]),
            Err(DecodeError::InvalidLength {
                expected: DISCOVERY_COMPLETE_LEN,
                actual: 23,
            })
        );
        let mut trailing_complete = [0u8; DISCOVERY_COMPLETE_LEN + 1];
        trailing_complete[..DISCOVERY_COMPLETE_LEN].copy_from_slice(&complete_buffer);
        assert_eq!(
            Message::decode(&trailing_complete),
            Err(DecodeError::InvalidLength {
                expected: DISCOVERY_COMPLETE_LEN,
                actual: DISCOVERY_COMPLETE_LEN + 1,
            })
        );
    }

    #[test]
    fn rejects_nonzero_discovery_complete_reserved_field() {
        let message = DiscoveryComplete {
            request_id: 1,
            status: 0,
        };
        let mut buffer = [0u8; DISCOVERY_COMPLETE_LEN];
        assert_eq!(message.encode(&mut buffer), Ok(DISCOVERY_COMPLETE_LEN));
        buffer[20..24].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            DiscoveryComplete::decode(&buffer),
            Err(DecodeError::NonZeroReserved { actual: 1 })
        );
    }

    #[test]
    fn preserves_status_sign_and_saved_results() {
        for status in [i32::MIN, -16, -1, 0, 1, 16, i32::MAX] {
            let saved = DiscoveryResult { status };
            let message = saved.response(42);
            let mut buffer = [0u8; DISCOVERY_COMPLETE_LEN];
            assert_eq!(message.encode(&mut buffer), Ok(DISCOVERY_COMPLETE_LEN));
            assert_eq!(DiscoveryComplete::decode(&buffer), Ok(message));
            assert_eq!(message.result(), saved);
            assert_eq!(saved.response(43).status, message.status);
            assert_eq!(saved.response(43).request_id(), 43);
        }
    }

    #[test]
    fn preserves_maximum_identifiers_tokens_and_endpoints() {
        let hello = DriverHello {
            request_id: u64::MAX,
            token: u64::MAX,
            control_endpoint: u64::MAX,
        };
        let hello_buffer = encoded(Message::DriverHello(hello));
        assert_eq!(DriverHello::decode(&hello_buffer), Ok(hello));

        let start = StartDiscovery {
            request_id: u64::MAX,
            token: u64::MAX,
            response_endpoint: u64::MAX,
        };
        let start_buffer = encoded(Message::StartDiscovery(start));
        assert_eq!(StartDiscovery::decode(&start_buffer), Ok(start));

        let complete = DiscoveryComplete {
            request_id: u64::MAX,
            status: 0,
        };
        let mut complete_buffer = [0u8; DISCOVERY_COMPLETE_LEN];
        assert_eq!(
            complete.encode(&mut complete_buffer),
            Ok(DISCOVERY_COMPLETE_LEN)
        );
        assert_eq!(DiscoveryComplete::decode(&complete_buffer), Ok(complete));
    }

    #[test]
    fn reports_encode_buffer_shortage_for_every_message() {
        let messages = [
            Message::DriverHello(DriverHello {
                request_id: 1,
                token: 2,
                control_endpoint: 3,
            }),
            Message::StartDiscovery(StartDiscovery {
                request_id: 1,
                token: 2,
                response_endpoint: 3,
            }),
            Message::DiscoveryComplete(DiscoveryComplete {
                request_id: 1,
                status: 0,
            }),
        ];
        for message in messages {
            let required = message.encoded_len();
            let mut buffer = [0u8; DRIVER_HELLO_LEN];
            assert_eq!(
                message.encode(&mut buffer[..required - 1]),
                Err(EncodeError::BufferTooSmall {
                    required,
                    actual: required - 1,
                })
            );
        }
    }

    #[test]
    fn opcode_specific_decoder_rejects_another_known_opcode() {
        let start = StartDiscovery {
            request_id: 1,
            token: 2,
            response_endpoint: 3,
        };
        let buffer = encoded(Message::StartDiscovery(start));
        assert_eq!(
            DriverHello::decode(&buffer),
            Err(DecodeError::UnexpectedOpcode {
                expected: Opcode::DriverHello,
                actual: Opcode::StartDiscovery,
            })
        );
    }
}
