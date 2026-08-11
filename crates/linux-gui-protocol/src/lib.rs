#![no_std]

use core::fmt;

pub const MAGIC: u32 = 0x4955_474c;
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 16;
pub const LAUNCH_REQUEST_LEN: usize = 24;
pub const LAUNCH_RESPONSE_LEN: usize = 32;

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Opcode {
    Launch = 0x0001,
    LaunchResponse = 0x8001,
}

impl Opcode {
    pub const fn wire_value(self) -> u16 {
        self as u16
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LinuxApplication {
    XTerm = 1,
}

impl LinuxApplication {
    pub const fn wire_value(self) -> u32 {
        self as u32
    }

    pub const fn host_name(self) -> &'static str {
        match self {
            Self::XTerm => "xterm",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    BufferTooSmall { required: usize, actual: usize },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    InvalidLength { expected: usize, actual: usize },
    InvalidMagic(u32),
    UnsupportedVersion(u16),
    UnknownOpcode(u16),
    UnexpectedOpcode { expected: Opcode, actual: Opcode },
    UnknownApplication(u32),
    NonZeroReserved(u32),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    formatter,
                    "invalid length: expected {expected}, actual {actual}"
                )
            }
            Self::InvalidMagic(actual) => write!(formatter, "invalid magic: {actual:#010x}"),
            Self::UnsupportedVersion(actual) => {
                write!(formatter, "unsupported version: {actual}")
            }
            Self::UnknownOpcode(actual) => write!(formatter, "unknown opcode: {actual:#06x}"),
            Self::UnexpectedOpcode { expected, actual } => write!(
                formatter,
                "unexpected opcode: expected {:#06x}, actual {:#06x}",
                expected.wire_value(),
                actual.wire_value()
            ),
            Self::UnknownApplication(actual) => {
                write!(formatter, "unknown Linux application: {actual}")
            }
            Self::NonZeroReserved(actual) => {
                write!(formatter, "reserved field must be zero: {actual:#010x}")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchRequest {
    pub request_id: u64,
    pub application: LinuxApplication,
}

impl LaunchRequest {
    pub const fn opcode(&self) -> Opcode {
        Opcode::Launch
    }

    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn encoded_len(&self) -> usize {
        LAUNCH_REQUEST_LEN
    }

    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        require_encode_len(buffer, LAUNCH_REQUEST_LEN)?;
        write_header(buffer, self.opcode(), self.request_id);
        write_u32(buffer, 16, self.application.wire_value());
        write_u32(buffer, 20, 0);
        Ok(LAUNCH_REQUEST_LEN)
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, DecodeError> {
        require_decode_len(buffer, LAUNCH_REQUEST_LEN)?;
        let request_id = decode_header(buffer, Opcode::Launch)?;
        require_zero(buffer, 20)?;
        let application = match read_u32(buffer, 16) {
            1 => LinuxApplication::XTerm,
            actual => return Err(DecodeError::UnknownApplication(actual)),
        };
        Ok(Self {
            request_id,
            application,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LaunchResponse {
    pub request_id: u64,
    pub status: i32,
    pub instance: u64,
}

impl LaunchResponse {
    pub const fn opcode(&self) -> Opcode {
        Opcode::LaunchResponse
    }

    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn encoded_len(&self) -> usize {
        LAUNCH_RESPONSE_LEN
    }

    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        require_encode_len(buffer, LAUNCH_RESPONSE_LEN)?;
        write_header(buffer, self.opcode(), self.request_id);
        buffer[16..20].copy_from_slice(&self.status.to_le_bytes());
        write_u32(buffer, 20, 0);
        write_u64(buffer, 24, self.instance);
        Ok(LAUNCH_RESPONSE_LEN)
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, DecodeError> {
        require_decode_len(buffer, LAUNCH_RESPONSE_LEN)?;
        let request_id = decode_header(buffer, Opcode::LaunchResponse)?;
        require_zero(buffer, 20)?;
        Ok(Self {
            request_id,
            status: i32::from_le_bytes(buffer[16..20].try_into().unwrap_or([0; 4])),
            instance: read_u64(buffer, 24),
        })
    }
}

fn require_encode_len(buffer: &[u8], required: usize) -> Result<(), EncodeError> {
    if buffer.len() < required {
        Err(EncodeError::BufferTooSmall {
            required,
            actual: buffer.len(),
        })
    } else {
        Ok(())
    }
}

fn require_decode_len(buffer: &[u8], expected: usize) -> Result<(), DecodeError> {
    if buffer.len() == expected {
        Ok(())
    } else {
        Err(DecodeError::InvalidLength {
            expected,
            actual: buffer.len(),
        })
    }
}

fn write_header(buffer: &mut [u8], opcode: Opcode, request_id: u64) {
    write_u32(buffer, 0, MAGIC);
    buffer[4..6].copy_from_slice(&VERSION.to_le_bytes());
    buffer[6..8].copy_from_slice(&opcode.wire_value().to_le_bytes());
    write_u64(buffer, 8, request_id);
}

fn decode_header(buffer: &[u8], expected: Opcode) -> Result<u64, DecodeError> {
    let magic = read_u32(buffer, 0);
    if magic != MAGIC {
        return Err(DecodeError::InvalidMagic(magic));
    }
    let version = u16::from_le_bytes([buffer[4], buffer[5]]);
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let raw_opcode = u16::from_le_bytes([buffer[6], buffer[7]]);
    let opcode = match raw_opcode {
        0x0001 => Opcode::Launch,
        0x8001 => Opcode::LaunchResponse,
        actual => return Err(DecodeError::UnknownOpcode(actual)),
    };
    if opcode != expected {
        return Err(DecodeError::UnexpectedOpcode {
            expected,
            actual: opcode,
        });
    }
    Ok(read_u64(buffer, 8))
}

fn require_zero(buffer: &[u8], offset: usize) -> Result<(), DecodeError> {
    let actual = read_u32(buffer, offset);
    if actual == 0 {
        Ok(())
    } else {
        Err(DecodeError::NonZeroReserved(actual))
    }
}

fn read_u32(buffer: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
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

fn write_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_request_round_trip_and_golden_bytes() {
        let message = LaunchRequest {
            request_id: u64::MAX,
            application: LinuxApplication::XTerm,
        };
        let mut encoded = [0u8; LAUNCH_REQUEST_LEN];
        assert_eq!(message.encode(&mut encoded), Ok(LAUNCH_REQUEST_LEN));
        assert_eq!(
            encoded,
            [
                b'L', b'G', b'U', b'I', 1, 0, 1, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                1, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(LaunchRequest::decode(&encoded), Ok(message));
    }

    #[test]
    fn launch_response_round_trip_and_status_values() {
        for status in [i32::MIN, -16, 0, i32::MAX] {
            let message = LaunchResponse {
                request_id: 0x0102_0304_0506_0708,
                status,
                instance: u64::MAX,
            };
            let mut encoded = [0u8; LAUNCH_RESPONSE_LEN];
            assert_eq!(message.encode(&mut encoded), Ok(LAUNCH_RESPONSE_LEN));
            assert_eq!(LaunchResponse::decode(&encoded), Ok(message));
        }
    }

    #[test]
    fn malformed_messages_are_rejected() {
        let message = LaunchRequest {
            request_id: 1,
            application: LinuxApplication::XTerm,
        };
        let mut encoded = [0u8; LAUNCH_REQUEST_LEN];
        assert_eq!(message.encode(&mut encoded), Ok(LAUNCH_REQUEST_LEN));
        encoded[0] = 0;
        assert!(matches!(
            LaunchRequest::decode(&encoded),
            Err(DecodeError::InvalidMagic(_))
        ));
        encoded[0] = b'L';
        encoded[4] = 2;
        assert_eq!(
            LaunchRequest::decode(&encoded),
            Err(DecodeError::UnsupportedVersion(2))
        );
        encoded[4] = 1;
        encoded[6..8].copy_from_slice(&0x1234_u16.to_le_bytes());
        assert_eq!(
            LaunchRequest::decode(&encoded),
            Err(DecodeError::UnknownOpcode(0x1234))
        );
    }

    #[test]
    fn lengths_reserved_and_application_are_checked() {
        let mut encoded = [0u8; LAUNCH_REQUEST_LEN];
        let message = LaunchRequest {
            request_id: 1,
            application: LinuxApplication::XTerm,
        };
        assert_eq!(message.encode(&mut encoded), Ok(LAUNCH_REQUEST_LEN));
        assert!(matches!(
            LaunchRequest::decode(&encoded[..23]),
            Err(DecodeError::InvalidLength { .. })
        ));
        let mut excessive = [0u8; LAUNCH_REQUEST_LEN + 1];
        excessive[..LAUNCH_REQUEST_LEN].copy_from_slice(&encoded);
        assert!(matches!(
            LaunchRequest::decode(&excessive),
            Err(DecodeError::InvalidLength { .. })
        ));
        encoded[20] = 1;
        assert_eq!(
            LaunchRequest::decode(&encoded),
            Err(DecodeError::NonZeroReserved(1))
        );
        encoded[20] = 0;
        encoded[16..20].copy_from_slice(&2_u32.to_le_bytes());
        assert_eq!(
            LaunchRequest::decode(&encoded),
            Err(DecodeError::UnknownApplication(2))
        );
        assert!(matches!(
            message.encode(&mut encoded[..23]),
            Err(EncodeError::BufferTooSmall { .. })
        ));
    }
}
