#![no_std]

use core::fmt;

pub const MAGIC: u32 = 0x4955_474c;
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 16;
pub const LAUNCH_REQUEST_LEN: usize = 24;
pub const LAUNCH_RESPONSE_LEN: usize = 32;
pub const STATUS_REQUEST_LEN: usize = 24;
pub const STATUS_RESPONSE_LEN: usize = 32;
pub const MAX_BUNDLE_ID_LEN: usize = 128;
pub const MAX_USER_NAME_LEN: usize = 64;
pub const BUNDLE_LAUNCH_PREFIX_LEN: usize = 24;
pub const PREPARE_BUNDLE_PREFIX_LEN: usize = 40;
pub const PREPARE_BUNDLE_RESPONSE_LEN: usize = 24;

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Opcode {
    Launch = 0x0001,
    Status = 0x0002,
    LaunchBundle = 0x0003,
    PrepareBundle = 0x0004,
    LaunchResponse = 0x8001,
    StatusResponse = 0x8002,
    LaunchBundleResponse = 0x8003,
    PrepareBundleResponse = 0x8004,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrepareBundleRequest<'a> {
    pub request_id: u64,
    pub bundle_id: &'a str,
    pub source_path: &'a str,
    pub rootfs_offset: u64,
    pub rootfs_size: u64,
    pub rootfs_digest: &'a str,
}

impl<'a> PrepareBundleRequest<'a> {
    pub fn encoded_len(&self) -> usize {
        PREPARE_BUNDLE_PREFIX_LEN
            + self.bundle_id.len()
            + self.source_path.len()
            + self.rootfs_digest.len()
    }

    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        let length = self.encoded_len();
        require_encode_len(buffer, length)?;
        if !valid_bundle_id(self.bundle_id)
            || !valid_absolute_path(self.source_path)
            || self.rootfs_size == 0
            || !valid_sha256(self.rootfs_digest)
        {
            return Err(EncodeError::InvalidValue);
        }
        write_header(buffer, Opcode::PrepareBundle, self.request_id);
        buffer[16..18].copy_from_slice(&(self.bundle_id.len() as u16).to_le_bytes());
        buffer[18..20].copy_from_slice(&(self.source_path.len() as u16).to_le_bytes());
        buffer[20..28].copy_from_slice(&self.rootfs_offset.to_le_bytes());
        buffer[28..36].copy_from_slice(&self.rootfs_size.to_le_bytes());
        buffer[36..38].copy_from_slice(&(self.rootfs_digest.len() as u16).to_le_bytes());
        buffer[38..40].fill(0);
        let bundle_end = PREPARE_BUNDLE_PREFIX_LEN + self.bundle_id.len();
        let source_end = bundle_end + self.source_path.len();
        buffer[PREPARE_BUNDLE_PREFIX_LEN..bundle_end].copy_from_slice(self.bundle_id.as_bytes());
        buffer[bundle_end..source_end].copy_from_slice(self.source_path.as_bytes());
        buffer[source_end..length].copy_from_slice(self.rootfs_digest.as_bytes());
        Ok(length)
    }

    pub fn decode(buffer: &'a [u8]) -> Result<Self, DecodeError> {
        if buffer.len() < PREPARE_BUNDLE_PREFIX_LEN {
            return Err(DecodeError::InvalidLength {
                expected: PREPARE_BUNDLE_PREFIX_LEN,
                actual: buffer.len(),
            });
        }
        let request_id = decode_header(buffer, Opcode::PrepareBundle)?;
        let bundle_len = usize::from(u16::from_le_bytes([buffer[16], buffer[17]]));
        let source_len = usize::from(u16::from_le_bytes([buffer[18], buffer[19]]));
        let digest_len = usize::from(u16::from_le_bytes([buffer[36], buffer[37]]));
        let expected = PREPARE_BUNDLE_PREFIX_LEN + bundle_len + source_len + digest_len;
        if buffer[38..40] != [0, 0] || buffer.len() != expected {
            return Err(DecodeError::InvalidLength {
                expected,
                actual: buffer.len(),
            });
        }
        let bundle_end = PREPARE_BUNDLE_PREFIX_LEN + bundle_len;
        let source_end = bundle_end + source_len;
        let bundle_id = core::str::from_utf8(&buffer[PREPARE_BUNDLE_PREFIX_LEN..bundle_end])
            .map_err(|_| DecodeError::InvalidUtf8)?;
        let source_path = core::str::from_utf8(&buffer[bundle_end..source_end])
            .map_err(|_| DecodeError::InvalidUtf8)?;
        let rootfs_digest =
            core::str::from_utf8(&buffer[source_end..]).map_err(|_| DecodeError::InvalidUtf8)?;
        if !valid_bundle_id(bundle_id) {
            return Err(DecodeError::InvalidBundleId);
        }
        if !valid_absolute_path(source_path) || !valid_sha256(rootfs_digest) {
            return Err(DecodeError::InvalidText);
        }
        let rootfs_size = read_u64(buffer, 28);
        if rootfs_size == 0 {
            return Err(DecodeError::InvalidLength {
                expected: 1,
                actual: 0,
            });
        }
        Ok(Self {
            request_id,
            bundle_id,
            source_path,
            rootfs_offset: read_u64(buffer, 20),
            rootfs_size,
            rootfs_digest,
        })
    }
}

fn valid_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && !value.contains('\0')
        && !value.contains("//")
        && value
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrepareBundleResponse {
    pub request_id: u64,
    pub status: i32,
}

impl PrepareBundleResponse {
    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        require_encode_len(buffer, PREPARE_BUNDLE_RESPONSE_LEN)?;
        write_header(buffer, Opcode::PrepareBundleResponse, self.request_id);
        buffer[16..20].copy_from_slice(&self.status.to_le_bytes());
        buffer[20..24].fill(0);
        Ok(PREPARE_BUNDLE_RESPONSE_LEN)
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, DecodeError> {
        require_decode_len(buffer, PREPARE_BUNDLE_RESPONSE_LEN)?;
        let request_id = decode_header(buffer, Opcode::PrepareBundleResponse)?;
        require_zero(buffer, 20)?;
        Ok(Self {
            request_id,
            status: i32::from_le_bytes(buffer[16..20].try_into().unwrap_or([0; 4])),
        })
    }
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
    XCalc = 2,
    XClock = 3,
}

impl LinuxApplication {
    pub const fn wire_value(self) -> u32 {
        self as u32
    }

    pub const fn host_name(self) -> &'static str {
        match self {
            Self::XTerm => "xterm",
            Self::XCalc => "xcalc",
            Self::XClock => "xclock",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    BufferTooSmall { required: usize, actual: usize },
    InvalidValue,
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
    InvalidBoolean(u32),
    InvalidUtf8,
    InvalidText,
    InvalidBundleId,
    InvalidUserName,
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
            Self::InvalidBoolean(actual) => {
                write!(formatter, "boolean field must be zero or one: {actual}")
            }
            Self::InvalidUtf8 => write!(formatter, "string field is not valid UTF-8"),
            Self::InvalidText => write!(formatter, "string field has an invalid value"),
            Self::InvalidBundleId => write!(formatter, "invalid Linux application bundle ID"),
            Self::InvalidUserName => write!(formatter, "invalid Linux application user name"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleLaunchRequest<'a> {
    pub request_id: u64,
    pub bundle_id: &'a str,
    pub user: &'a str,
}

impl BundleLaunchRequest<'_> {
    pub const fn opcode(&self) -> Opcode {
        Opcode::LaunchBundle
    }

    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub fn encoded_len(&self) -> usize {
        BUNDLE_LAUNCH_PREFIX_LEN + self.bundle_id.len() + self.user.len()
    }

    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        let length = self.encoded_len();
        require_encode_len(buffer, length)?;
        if !valid_bundle_id(self.bundle_id) || !valid_user_name(self.user) {
            return Err(EncodeError::InvalidValue);
        }
        write_header(buffer, self.opcode(), self.request_id);
        buffer[16..18].copy_from_slice(&(self.bundle_id.len() as u16).to_le_bytes());
        buffer[18..20].copy_from_slice(&(self.user.len() as u16).to_le_bytes());
        buffer[20..24].copy_from_slice(&0u32.to_le_bytes());
        let bundle_end = BUNDLE_LAUNCH_PREFIX_LEN + self.bundle_id.len();
        buffer[BUNDLE_LAUNCH_PREFIX_LEN..bundle_end].copy_from_slice(self.bundle_id.as_bytes());
        buffer[bundle_end..length].copy_from_slice(self.user.as_bytes());
        Ok(length)
    }

    pub fn decode(buffer: &'_ [u8]) -> Result<BundleLaunchRequest<'_>, DecodeError> {
        if buffer.len() < BUNDLE_LAUNCH_PREFIX_LEN {
            return Err(DecodeError::InvalidLength {
                expected: BUNDLE_LAUNCH_PREFIX_LEN,
                actual: buffer.len(),
            });
        }
        let request_id = decode_header(buffer, Opcode::LaunchBundle)?;
        let bundle_len = usize::from(u16::from_le_bytes([buffer[16], buffer[17]]));
        let user_len = usize::from(u16::from_le_bytes([buffer[18], buffer[19]]));
        let reserved = u32::from_le_bytes([buffer[20], buffer[21], buffer[22], buffer[23]]);
        if reserved != 0 {
            return Err(DecodeError::NonZeroReserved(reserved));
        }
        let expected = BUNDLE_LAUNCH_PREFIX_LEN + bundle_len + user_len;
        if buffer.len() != expected {
            return Err(DecodeError::InvalidLength {
                expected,
                actual: buffer.len(),
            });
        }
        let bundle_end = BUNDLE_LAUNCH_PREFIX_LEN + bundle_len;
        let bundle_id = core::str::from_utf8(&buffer[BUNDLE_LAUNCH_PREFIX_LEN..bundle_end])
            .map_err(|_| DecodeError::InvalidUtf8)?;
        let user =
            core::str::from_utf8(&buffer[bundle_end..]).map_err(|_| DecodeError::InvalidUtf8)?;
        if !valid_bundle_id(bundle_id) {
            return Err(DecodeError::InvalidBundleId);
        }
        if !valid_user_name(user) {
            return Err(DecodeError::InvalidUserName);
        }
        Ok(BundleLaunchRequest {
            request_id,
            bundle_id,
            user,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BundleLaunchResponse {
    pub request_id: u64,
    pub status: i32,
    pub instance: u64,
}

impl BundleLaunchResponse {
    pub const fn opcode(&self) -> Opcode {
        Opcode::LaunchBundleResponse
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
        let request_id = decode_header(buffer, Opcode::LaunchBundleResponse)?;
        require_zero(buffer, 20)?;
        Ok(Self {
            request_id,
            status: i32::from_le_bytes(buffer[16..20].try_into().unwrap_or([0; 4])),
            instance: read_u64(buffer, 24),
        })
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
            2 => LinuxApplication::XCalc,
            3 => LinuxApplication::XClock,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusRequest {
    pub request_id: u64,
    pub instance: u64,
}

impl StatusRequest {
    pub const fn opcode(&self) -> Opcode {
        Opcode::Status
    }

    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn encoded_len(&self) -> usize {
        STATUS_REQUEST_LEN
    }

    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        require_encode_len(buffer, STATUS_REQUEST_LEN)?;
        write_header(buffer, self.opcode(), self.request_id);
        write_u64(buffer, 16, self.instance);
        Ok(STATUS_REQUEST_LEN)
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, DecodeError> {
        require_decode_len(buffer, STATUS_REQUEST_LEN)?;
        let request_id = decode_header(buffer, Opcode::Status)?;
        Ok(Self {
            request_id,
            instance: read_u64(buffer, 16),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusResponse {
    pub request_id: u64,
    pub status: i32,
    pub running: bool,
    pub instance: u64,
}

impl StatusResponse {
    pub const fn opcode(&self) -> Opcode {
        Opcode::StatusResponse
    }

    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn encoded_len(&self) -> usize {
        STATUS_RESPONSE_LEN
    }

    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        require_encode_len(buffer, STATUS_RESPONSE_LEN)?;
        write_header(buffer, self.opcode(), self.request_id);
        buffer[16..20].copy_from_slice(&self.status.to_le_bytes());
        write_u32(buffer, 20, u32::from(self.running));
        write_u64(buffer, 24, self.instance);
        Ok(STATUS_RESPONSE_LEN)
    }

    pub fn decode(buffer: &[u8]) -> Result<Self, DecodeError> {
        require_decode_len(buffer, STATUS_RESPONSE_LEN)?;
        let request_id = decode_header(buffer, Opcode::StatusResponse)?;
        let running = match read_u32(buffer, 20) {
            0 => false,
            1 => true,
            actual => return Err(DecodeError::InvalidBoolean(actual)),
        };
        Ok(Self {
            request_id,
            status: i32::from_le_bytes(buffer[16..20].try_into().unwrap_or([0; 4])),
            running,
            instance: read_u64(buffer, 24),
        })
    }
}

pub fn decode_opcode(buffer: &[u8]) -> Result<Opcode, DecodeError> {
    if buffer.len() < HEADER_LEN {
        return Err(DecodeError::InvalidLength {
            expected: HEADER_LEN,
            actual: buffer.len(),
        });
    }
    let magic = read_u32(buffer, 0);
    if magic != MAGIC {
        return Err(DecodeError::InvalidMagic(magic));
    }
    let version = u16::from_le_bytes([buffer[4], buffer[5]]);
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    match u16::from_le_bytes([buffer[6], buffer[7]]) {
        0x0001 => Ok(Opcode::Launch),
        0x0002 => Ok(Opcode::Status),
        0x0003 => Ok(Opcode::LaunchBundle),
        0x0004 => Ok(Opcode::PrepareBundle),
        0x8001 => Ok(Opcode::LaunchResponse),
        0x8002 => Ok(Opcode::StatusResponse),
        0x8003 => Ok(Opcode::LaunchBundleResponse),
        0x8004 => Ok(Opcode::PrepareBundleResponse),
        actual => Err(DecodeError::UnknownOpcode(actual)),
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
    let opcode = decode_opcode(buffer)?;
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

fn valid_bundle_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_BUNDLE_ID_LEN
        && !value.starts_with('.')
        && !value.ends_with('.')
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
}

fn valid_user_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_USER_NAME_LEN
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
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
    fn every_supported_application_has_a_stable_wire_value_and_host_name() {
        assert_eq!(LinuxApplication::XTerm.wire_value(), 1);
        assert_eq!(LinuxApplication::XTerm.host_name(), "xterm");
        assert_eq!(LinuxApplication::XCalc.wire_value(), 2);
        assert_eq!(LinuxApplication::XCalc.host_name(), "xcalc");
        assert_eq!(LinuxApplication::XClock.wire_value(), 3);
        assert_eq!(LinuxApplication::XClock.host_name(), "xclock");

        for application in [
            LinuxApplication::XTerm,
            LinuxApplication::XCalc,
            LinuxApplication::XClock,
        ] {
            let request = LaunchRequest {
                request_id: 7,
                application,
            };
            let mut encoded = [0u8; LAUNCH_REQUEST_LEN];
            assert_eq!(request.encode(&mut encoded), Ok(LAUNCH_REQUEST_LEN));
            assert_eq!(LaunchRequest::decode(&encoded), Ok(request));
        }
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
    fn bundle_launch_round_trip_and_golden_bytes() {
        let request = BundleLaunchRequest {
            request_id: 0x0102_0304_0506_0708,
            bundle_id: "org.example.editor",
            user: "alice",
        };
        let mut encoded = [0u8; 64];
        let length = request.encode(&mut encoded).unwrap();
        assert_eq!(length, BUNDLE_LAUNCH_PREFIX_LEN + 18 + 5);
        assert_eq!(&encoded[..4], b"LGUI");
        assert_eq!(&encoded[4..8], &[1, 0, 3, 0]);
        assert_eq!(&encoded[8..16], &[8, 7, 6, 5, 4, 3, 2, 1]);
        assert_eq!(&encoded[16..24], &[18, 0, 5, 0, 0, 0, 0, 0]);
        assert_eq!(&encoded[24..42], b"org.example.editor");
        assert_eq!(&encoded[42..length], b"alice");
        assert_eq!(BundleLaunchRequest::decode(&encoded[..length]), Ok(request));

        let response = BundleLaunchResponse {
            request_id: request.request_id,
            status: -13,
            instance: u64::MAX,
        };
        let mut response_bytes = [0u8; LAUNCH_RESPONSE_LEN];
        assert_eq!(
            response.encode(&mut response_bytes),
            Ok(LAUNCH_RESPONSE_LEN)
        );
        assert_eq!(BundleLaunchResponse::decode(&response_bytes), Ok(response));
    }

    #[test]
    fn prepare_bundle_round_trip_and_golden_bytes() {
        let request = PrepareBundleRequest {
            request_id: 0x0102_0304_0506_0708,
            bundle_id: "org.mochios.chromium",
            source_path: "/system/samples/Chromium-x86_64.mpkg",
            rootfs_offset: 4096,
            rootfs_size: 242_634_752,
            rootfs_digest: "b18cad88465a5303a4c3dfcf321d2a6541d7e8759f62286fbc3f8fa17a552450",
        };
        let mut encoded = [0u8; 256];
        let length = request.encode(&mut encoded).unwrap();
        assert_eq!(length, request.encoded_len());
        assert_eq!(&encoded[..4], b"LGUI");
        assert_eq!(&encoded[4..8], &[1, 0, 4, 0]);
        assert_eq!(&encoded[16..20], &[20, 0, 36, 0]);
        assert_eq!(&encoded[20..28], &4096u64.to_le_bytes());
        assert_eq!(
            PrepareBundleRequest::decode(&encoded[..length]),
            Ok(request)
        );

        let response = PrepareBundleResponse {
            request_id: request.request_id,
            status: -5,
        };
        let mut response_bytes = [0u8; PREPARE_BUNDLE_RESPONSE_LEN];
        assert_eq!(
            response.encode(&mut response_bytes),
            Ok(PREPARE_BUNDLE_RESPONSE_LEN)
        );
        assert_eq!(PrepareBundleResponse::decode(&response_bytes), Ok(response));
    }

    #[test]
    fn bundle_launch_rejects_invalid_ids_lengths_and_reserved() {
        for bundle_id in [
            "",
            ".org.example",
            "org.example.",
            "org..example",
            "Org.example",
            "org/example",
        ] {
            let request = BundleLaunchRequest {
                request_id: 1,
                bundle_id,
                user: "alice",
            };
            let mut encoded = [0u8; 256];
            assert_eq!(request.encode(&mut encoded), Err(EncodeError::InvalidValue));
        }
        for user in ["", "Alice", "../root", "alice/user"] {
            let request = BundleLaunchRequest {
                request_id: 1,
                bundle_id: "org.example.editor",
                user,
            };
            let mut encoded = [0u8; 256];
            assert_eq!(request.encode(&mut encoded), Err(EncodeError::InvalidValue));
        }

        let request = BundleLaunchRequest {
            request_id: 1,
            bundle_id: "org.example.editor",
            user: "alice",
        };
        let mut encoded = [0u8; 64];
        let length = request.encode(&mut encoded).unwrap();
        assert!(matches!(
            request.encode(&mut encoded[..length - 1]),
            Err(EncodeError::BufferTooSmall { .. })
        ));
        encoded[20] = 1;
        assert_eq!(
            BundleLaunchRequest::decode(&encoded[..length]),
            Err(DecodeError::NonZeroReserved(1))
        );
        encoded[20] = 0;
        assert!(matches!(
            BundleLaunchRequest::decode(&encoded[..length - 1]),
            Err(DecodeError::InvalidLength { .. })
        ));
    }

    #[test]
    fn status_messages_round_trip_and_have_stable_bytes() {
        let request = StatusRequest {
            request_id: 0x0102_0304_0506_0708,
            instance: u64::MAX,
        };
        let mut encoded_request = [0u8; STATUS_REQUEST_LEN];
        assert_eq!(request.encode(&mut encoded_request), Ok(STATUS_REQUEST_LEN));
        assert_eq!(
            encoded_request,
            [
                b'L', b'G', b'U', b'I', 1, 0, 2, 0, 8, 7, 6, 5, 4, 3, 2, 1, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
            ]
        );
        assert_eq!(StatusRequest::decode(&encoded_request), Ok(request));
        assert_eq!(decode_opcode(&encoded_request), Ok(Opcode::Status));

        for (status, running) in [(0, false), (0, true), (-5, false)] {
            let response = StatusResponse {
                request_id: request.request_id,
                status,
                running,
                instance: request.instance,
            };
            let mut encoded_response = [0u8; STATUS_RESPONSE_LEN];
            assert_eq!(
                response.encode(&mut encoded_response),
                Ok(STATUS_RESPONSE_LEN)
            );
            assert_eq!(StatusResponse::decode(&encoded_response), Ok(response));
            assert_eq!(decode_opcode(&encoded_response), Ok(Opcode::StatusResponse));
        }
    }

    #[test]
    fn status_response_rejects_non_boolean_running_value() {
        let response = StatusResponse {
            request_id: 1,
            status: 0,
            running: false,
            instance: 9,
        };
        let mut encoded = [0u8; STATUS_RESPONSE_LEN];
        assert_eq!(response.encode(&mut encoded), Ok(STATUS_RESPONSE_LEN));
        encoded[20..24].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            StatusResponse::decode(&encoded),
            Err(DecodeError::InvalidBoolean(2))
        );
        assert!(matches!(
            response.encode(&mut encoded[..STATUS_RESPONSE_LEN - 1]),
            Err(EncodeError::BufferTooSmall { .. })
        ));
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
        encoded[16..20].copy_from_slice(&4_u32.to_le_bytes());
        assert_eq!(
            LaunchRequest::decode(&encoded),
            Err(DecodeError::UnknownApplication(4))
        );
        assert!(matches!(
            message.encode(&mut encoded[..23]),
            Err(EncodeError::BufferTooSmall { .. })
        ));
    }
}
