#![no_std]

use core::fmt;

pub const MAGIC: u32 = 0x5052_444d;
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 16;
pub const GRANT_REQUEST_PREFIX_LEN: usize = 40;
pub const GRANT_RESPONSE_LEN: usize = 32;
pub const NETWORK_REQUEST_PREFIX_LEN: usize = 32;
pub const NETWORK_RESPONSE_LEN: usize = 24;
pub const MAX_BUNDLE_ID_LEN: usize = 128;
pub const MAX_USER_NAME_LEN: usize = 64;
pub const MAX_PATH_LEN: usize = 512;

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Opcode {
    GrantDirectory = 0x0001,
    GrantDirectoryResponse = 0x8001,
    RequestNetwork = 0x0002,
    RequestNetworkResponse = 0x8002,
}

impl Opcode {
    pub const fn wire_value(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Access(u32);

impl Access {
    pub const READ: Self = Self(1);
    pub const READ_WRITE: Self = Self(3);

    pub const fn wire_value(self) -> u32 {
        self.0
    }

    pub const fn writable(self) -> bool {
        self.0 == Self::READ_WRITE.0
    }

    fn from_wire(value: u32) -> Result<Self, DecodeError> {
        match value {
            1 => Ok(Self::READ),
            3 => Ok(Self::READ_WRITE),
            _ => Err(DecodeError::InvalidAccess(value)),
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
    NonZeroReserved(u32),
    InvalidAccess(u32),
    InvalidUtf8,
    InvalidBundleId,
    InvalidUserName,
    InvalidPath,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantDirectoryRequest<'a> {
    pub request_id: u64,
    pub session_id: u64,
    pub access: Access,
    pub bundle_id: &'a str,
    pub user: &'a str,
    pub path: &'a str,
}

impl GrantDirectoryRequest<'_> {
    pub const fn opcode(&self) -> Opcode {
        Opcode::GrantDirectory
    }

    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub fn encoded_len(&self) -> usize {
        GRANT_REQUEST_PREFIX_LEN + self.bundle_id.len() + self.user.len() + self.path.len()
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        if !valid_bundle_id(self.bundle_id)
            || !valid_user_name(self.user)
            || !valid_portal_path(self.path)
            || self.session_id == 0
        {
            return Err(EncodeError::InvalidValue);
        }
        let length = self.encoded_len();
        require_output(output, length)?;
        write_header(output, self.opcode(), self.request_id);
        output[16..24].copy_from_slice(&self.session_id.to_le_bytes());
        output[24..28].copy_from_slice(&self.access.wire_value().to_le_bytes());
        output[28..30].copy_from_slice(&(self.bundle_id.len() as u16).to_le_bytes());
        output[30..32].copy_from_slice(&(self.user.len() as u16).to_le_bytes());
        output[32..34].copy_from_slice(&(self.path.len() as u16).to_le_bytes());
        output[34..40].fill(0);
        let bundle_end = GRANT_REQUEST_PREFIX_LEN + self.bundle_id.len();
        let user_end = bundle_end + self.user.len();
        output[GRANT_REQUEST_PREFIX_LEN..bundle_end].copy_from_slice(self.bundle_id.as_bytes());
        output[bundle_end..user_end].copy_from_slice(self.user.as_bytes());
        output[user_end..length].copy_from_slice(self.path.as_bytes());
        Ok(length)
    }

    pub fn decode(input: &'_ [u8]) -> Result<GrantDirectoryRequest<'_>, DecodeError> {
        if input.len() < GRANT_REQUEST_PREFIX_LEN {
            return Err(DecodeError::InvalidLength {
                expected: GRANT_REQUEST_PREFIX_LEN,
                actual: input.len(),
            });
        }
        let request_id = decode_header(input, Opcode::GrantDirectory)?;
        let session_id = read_u64(input, 16);
        let access = Access::from_wire(read_u32(input, 24))?;
        let bundle_len = usize::from(read_u16(input, 28));
        let user_len = usize::from(read_u16(input, 30));
        let path_len = usize::from(read_u16(input, 32));
        let reserved = u32::from_le_bytes([input[34], input[35], input[36], input[37]]);
        let reserved_tail = u16::from_le_bytes([input[38], input[39]]);
        if reserved != 0 || reserved_tail != 0 {
            return Err(DecodeError::NonZeroReserved(reserved | u32::from(reserved_tail)));
        }
        let expected = GRANT_REQUEST_PREFIX_LEN + bundle_len + user_len + path_len;
        if input.len() != expected {
            return Err(DecodeError::InvalidLength {
                expected,
                actual: input.len(),
            });
        }
        let bundle_end = GRANT_REQUEST_PREFIX_LEN + bundle_len;
        let user_end = bundle_end + user_len;
        let bundle_id = text(&input[GRANT_REQUEST_PREFIX_LEN..bundle_end])?;
        let user = text(&input[bundle_end..user_end])?;
        let path = text(&input[user_end..])?;
        if session_id == 0 || !valid_bundle_id(bundle_id) {
            return Err(DecodeError::InvalidBundleId);
        }
        if !valid_user_name(user) {
            return Err(DecodeError::InvalidUserName);
        }
        if !valid_portal_path(path) {
            return Err(DecodeError::InvalidPath);
        }
        Ok(GrantDirectoryRequest {
            request_id,
            session_id,
            access,
            bundle_id,
            user,
            path,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantDirectoryResponse {
    pub request_id: u64,
    pub status: i32,
    pub grant_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestNetworkRequest<'a> {
    pub request_id: u64,
    pub session_id: u64,
    pub bundle_id: &'a str,
    pub user: &'a str,
}

impl<'a> RequestNetworkRequest<'a> {
    pub fn encoded_len(&self) -> usize {
        NETWORK_REQUEST_PREFIX_LEN + self.bundle_id.len() + self.user.len()
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        if self.session_id == 0 || !valid_bundle_id(self.bundle_id) || !valid_user_name(self.user) {
            return Err(EncodeError::InvalidValue);
        }
        let length = self.encoded_len();
        require_output(output, length)?;
        write_header(output, Opcode::RequestNetwork, self.request_id);
        output[16..24].copy_from_slice(&self.session_id.to_le_bytes());
        output[24..26].copy_from_slice(&(self.bundle_id.len() as u16).to_le_bytes());
        output[26..28].copy_from_slice(&(self.user.len() as u16).to_le_bytes());
        output[28..32].fill(0);
        let bundle_end = NETWORK_REQUEST_PREFIX_LEN + self.bundle_id.len();
        output[NETWORK_REQUEST_PREFIX_LEN..bundle_end].copy_from_slice(self.bundle_id.as_bytes());
        output[bundle_end..length].copy_from_slice(self.user.as_bytes());
        Ok(length)
    }

    pub fn decode(input: &'a [u8]) -> Result<Self, DecodeError> {
        if input.len() < NETWORK_REQUEST_PREFIX_LEN {
            return Err(DecodeError::InvalidLength { expected: NETWORK_REQUEST_PREFIX_LEN, actual: input.len() });
        }
        let request_id = decode_header(input, Opcode::RequestNetwork)?;
        let session_id = read_u64(input, 16);
        let bundle_len = usize::from(read_u16(input, 24));
        let user_len = usize::from(read_u16(input, 26));
        let reserved = read_u32(input, 28);
        let expected = NETWORK_REQUEST_PREFIX_LEN + bundle_len + user_len;
        if reserved != 0 {
            return Err(DecodeError::NonZeroReserved(reserved));
        }
        if input.len() != expected {
            return Err(DecodeError::InvalidLength { expected, actual: input.len() });
        }
        let bundle_end = NETWORK_REQUEST_PREFIX_LEN + bundle_len;
        let bundle_id = text(&input[NETWORK_REQUEST_PREFIX_LEN..bundle_end])?;
        let user = text(&input[bundle_end..])?;
        if session_id == 0 || !valid_bundle_id(bundle_id) {
            return Err(DecodeError::InvalidBundleId);
        }
        if !valid_user_name(user) {
            return Err(DecodeError::InvalidUserName);
        }
        Ok(Self { request_id, session_id, bundle_id, user })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestNetworkResponse {
    pub request_id: u64,
    pub status: i32,
}

impl RequestNetworkResponse {
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        require_output(output, NETWORK_RESPONSE_LEN)?;
        write_header(output, Opcode::RequestNetworkResponse, self.request_id);
        output[16..20].copy_from_slice(&self.status.to_le_bytes());
        output[20..24].fill(0);
        Ok(NETWORK_RESPONSE_LEN)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        require_exact(input, NETWORK_RESPONSE_LEN)?;
        let request_id = decode_header(input, Opcode::RequestNetworkResponse)?;
        let reserved = read_u32(input, 20);
        if reserved != 0 {
            return Err(DecodeError::NonZeroReserved(reserved));
        }
        Ok(Self { request_id, status: i32::from_le_bytes(input[16..20].try_into().unwrap()) })
    }
}

impl GrantDirectoryResponse {
    pub const fn opcode(&self) -> Opcode {
        Opcode::GrantDirectoryResponse
    }

    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn encoded_len(&self) -> usize {
        GRANT_RESPONSE_LEN
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        require_output(output, GRANT_RESPONSE_LEN)?;
        if (self.status == 0) != (self.grant_id != 0) {
            return Err(EncodeError::InvalidValue);
        }
        write_header(output, self.opcode(), self.request_id);
        output[16..20].copy_from_slice(&self.status.to_le_bytes());
        output[20..24].fill(0);
        output[24..32].copy_from_slice(&self.grant_id.to_le_bytes());
        Ok(GRANT_RESPONSE_LEN)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        require_exact(input, GRANT_RESPONSE_LEN)?;
        let request_id = decode_header(input, Opcode::GrantDirectoryResponse)?;
        let status = i32::from_le_bytes([input[16], input[17], input[18], input[19]]);
        let reserved = read_u32(input, 20);
        if reserved != 0 {
            return Err(DecodeError::NonZeroReserved(reserved));
        }
        let grant_id = read_u64(input, 24);
        if (status == 0) != (grant_id != 0) {
            return Err(DecodeError::InvalidAccess(0));
        }
        Ok(Self {
            request_id,
            status,
            grant_id,
        })
    }
}

pub fn decode_opcode(input: &[u8]) -> Result<Opcode, DecodeError> {
    if input.len() < HEADER_LEN {
        return Err(DecodeError::InvalidLength {
            expected: HEADER_LEN,
            actual: input.len(),
        });
    }
    let magic = read_u32(input, 0);
    if magic != MAGIC {
        return Err(DecodeError::InvalidMagic(magic));
    }
    let version = read_u16(input, 4);
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    match read_u16(input, 6) {
        0x0001 => Ok(Opcode::GrantDirectory),
        0x8001 => Ok(Opcode::GrantDirectoryResponse),
        0x0002 => Ok(Opcode::RequestNetwork),
        0x8002 => Ok(Opcode::RequestNetworkResponse),
        value => Err(DecodeError::UnknownOpcode(value)),
    }
}

pub fn valid_portal_path(path: &str) -> bool {
    path.len() <= MAX_PATH_LEN
        && path.starts_with('/')
        && path != "/"
        && !path.ends_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains('\0'))
}

fn valid_bundle_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_BUNDLE_ID_LEN
        && value.split('.').count() >= 2
        && value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
}

fn valid_user_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_USER_NAME_LEN
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
        })
}

fn write_header(output: &mut [u8], opcode: Opcode, request_id: u64) {
    output[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    output[4..6].copy_from_slice(&VERSION.to_le_bytes());
    output[6..8].copy_from_slice(&opcode.wire_value().to_le_bytes());
    output[8..16].copy_from_slice(&request_id.to_le_bytes());
}

fn decode_header(input: &[u8], expected: Opcode) -> Result<u64, DecodeError> {
    let actual = decode_opcode(input)?;
    if actual != expected {
        return Err(DecodeError::UnexpectedOpcode { expected, actual });
    }
    Ok(read_u64(input, 8))
}

fn require_output(output: &[u8], required: usize) -> Result<(), EncodeError> {
    if output.len() < required {
        Err(EncodeError::BufferTooSmall {
            required,
            actual: output.len(),
        })
    } else {
        Ok(())
    }
}

fn require_exact(input: &[u8], expected: usize) -> Result<(), DecodeError> {
    if input.len() == expected {
        Ok(())
    } else {
        Err(DecodeError::InvalidLength {
            expected,
            actual: input.len(),
        })
    }
}

fn text(input: &[u8]) -> Result<&str, DecodeError> {
    core::str::from_utf8(input).map_err(|_| DecodeError::InvalidUtf8)
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([input[offset], input[offset + 1]])
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
        input[offset + 4],
        input[offset + 5],
        input[offset + 6],
        input[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request<'a>() -> GrantDirectoryRequest<'a> {
        GrantDirectoryRequest {
            request_id: u64::MAX,
            session_id: 9,
            access: Access::READ_WRITE,
            bundle_id: "org.example.editor",
            user: "alice",
            path: "/home/alice/Develop",
        }
    }

    #[test]
    fn request_round_trip_and_golden_prefix() {
        let request = request();
        let mut bytes = [0u8; 128];
        let length = request.encode(&mut bytes).unwrap();
        assert_eq!(length, request.encoded_len());
        assert_eq!(
            &bytes[..40],
            &[
                0x4d, 0x44, 0x52, 0x50, 1, 0, 1, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 9, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 18, 0, 5, 0, 19, 0, 0,
                0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(GrantDirectoryRequest::decode(&bytes[..length]), Ok(request));
    }

    #[test]
    fn response_round_trip_and_golden_bytes() {
        let response = GrantDirectoryResponse {
            request_id: 7,
            status: 0,
            grant_id: u64::MAX,
        };
        let mut bytes = [0u8; GRANT_RESPONSE_LEN];
        response.encode(&mut bytes).unwrap();
        assert_eq!(
            bytes,
            [
                0x4d, 0x44, 0x52, 0x50, 1, 0, 1, 0x80, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ]
        );
        assert_eq!(GrantDirectoryResponse::decode(&bytes), Ok(response));
    }

    #[test]
    fn malformed_headers_lengths_and_reserved_are_rejected() {
        let mut bytes = [0u8; 128];
        let length = request().encode(&mut bytes).unwrap();
        let mut bad = bytes;
        bad[0] = 0;
        assert!(matches!(GrantDirectoryRequest::decode(&bad[..length]), Err(DecodeError::InvalidMagic(_))));
        bad = bytes;
        bad[4] = 2;
        assert!(matches!(GrantDirectoryRequest::decode(&bad[..length]), Err(DecodeError::UnsupportedVersion(2))));
        bad = bytes;
        bad[6] = 2;
        assert!(matches!(GrantDirectoryRequest::decode(&bad[..length]), Err(DecodeError::UnexpectedOpcode { actual: Opcode::RequestNetwork, .. })));
        bad = bytes;
        bad[34] = 1;
        assert!(matches!(GrantDirectoryRequest::decode(&bad[..length]), Err(DecodeError::NonZeroReserved(_))));
        assert!(matches!(GrantDirectoryRequest::decode(&bytes[..length - 1]), Err(DecodeError::InvalidLength { .. })));
        assert!(matches!(GrantDirectoryRequest::decode(&bytes[..GRANT_REQUEST_PREFIX_LEN - 1]), Err(DecodeError::InvalidLength { .. })));
    }

    #[test]
    fn values_and_output_are_validated() {
        assert!(valid_portal_path("/home/alice/Develop"));
        assert!(!valid_portal_path("/"));
        assert!(!valid_portal_path("/home/../root"));
        let mut short = [0u8; 8];
        assert!(matches!(request().encode(&mut short), Err(EncodeError::BufferTooSmall { .. })));
        let invalid = GrantDirectoryRequest { path: "/tmp/../root", ..request() };
        let mut output = [0u8; 128];
        assert_eq!(invalid.encode(&mut output), Err(EncodeError::InvalidValue));
    }

    #[test]
    fn response_requires_consistent_status_and_grant() {
        let mut bytes = [0u8; GRANT_RESPONSE_LEN];
        assert_eq!(GrantDirectoryResponse { request_id: 1, status: 0, grant_id: 0 }.encode(&mut bytes), Err(EncodeError::InvalidValue));
        assert_eq!(GrantDirectoryResponse { request_id: 1, status: -13, grant_id: 1 }.encode(&mut bytes), Err(EncodeError::InvalidValue));
        GrantDirectoryResponse { request_id: 1, status: -13, grant_id: 0 }.encode(&mut bytes).unwrap();
        assert_eq!(GrantDirectoryResponse::decode(&bytes).unwrap().status, -13);
    }
}
