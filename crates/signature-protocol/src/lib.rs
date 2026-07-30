#![no_std]

use core::fmt;

pub const MAGIC: u32 = 0x4749_534d;
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 24;
pub const BEGIN_LEN: usize = HEADER_LEN + 40;
pub const FINISH_LEN: usize = HEADER_LEN;
pub const ERROR_LEN: usize = HEADER_LEN + 8;
pub const UPDATE_NOTIFICATION_LEN: usize = HEADER_LEN + 16;
pub const VERIFIED_FIXED_LEN: usize = HEADER_LEN + 112;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    VerifyBegin = 0x0001,
    VerifyChunk = 0x0002,
    VerifyFinish = 0x0003,
    TrustUpdated = 0x0100,
    RevocationsUpdated = 0x0101,
    Status = 0x8000,
    Verified = 0x8003,
    Error = 0xffff,
}

impl Opcode {
    pub const fn wire_value(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    BufferTooSmall { required: usize, actual: usize },
    InvalidOpcode,
    ValueTooLong,
    TooManyCapabilities,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    InvalidLength,
    InvalidMagic(u32),
    UnsupportedVersion(u16),
    UnknownOpcode(u16),
    UnexpectedOpcode { expected: Opcode, actual: Opcode },
    UnexpectedUpdateOpcode(Opcode),
    NonZeroFlags(u32),
    NonZeroReserved,
    InvalidUtf8,
    InvalidText,
    InvalidCapabilityList,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "{self:?}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Header {
    opcode: Opcode,
    request_id: u64,
    payload_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyBegin {
    pub request_id: u64,
    pub package_len: u64,
    pub package_digest: [u8; 32],
}

impl VerifyBegin {
    pub const fn opcode(&self) -> Opcode {
        Opcode::VerifyBegin
    }
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }
    pub const fn encoded_len(&self) -> usize {
        BEGIN_LEN
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        require(output, BEGIN_LEN)?;
        write_header(output, self.opcode(), self.request_id, 40);
        output[24..32].copy_from_slice(&self.package_len.to_le_bytes());
        output[32..64].copy_from_slice(&self.package_digest);
        Ok(BEGIN_LEN)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let header = expected_header(input, Opcode::VerifyBegin)?;
        if input.len() != BEGIN_LEN || header.payload_len != 40 {
            return Err(DecodeError::InvalidLength);
        }
        let mut digest = [0; 32];
        digest.copy_from_slice(&input[32..64]);
        Ok(Self {
            request_id: header.request_id,
            package_len: read_u64(input, 24),
            package_digest: digest,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyChunk<'a> {
    pub request_id: u64,
    pub offset: u64,
    pub bytes: &'a [u8],
}

impl VerifyChunk<'_> {
    pub const fn opcode(&self) -> Opcode {
        Opcode::VerifyChunk
    }
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }
    pub const fn encoded_len(&self) -> usize {
        HEADER_LEN + 8 + self.bytes.len()
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let length = self.encoded_len();
        require(output, length)?;
        let payload_len =
            u32::try_from(length - HEADER_LEN).map_err(|_| EncodeError::ValueTooLong)?;
        write_header(output, self.opcode(), self.request_id, payload_len);
        output[24..32].copy_from_slice(&self.offset.to_le_bytes());
        output[32..length].copy_from_slice(self.bytes);
        Ok(length)
    }

    pub fn decode(input: &[u8]) -> Result<VerifyChunk<'_>, DecodeError> {
        let header = expected_header(input, Opcode::VerifyChunk)?;
        if header.payload_len < 8 {
            return Err(DecodeError::InvalidLength);
        }
        Ok(VerifyChunk {
            request_id: header.request_id,
            offset: read_u64(input, 24),
            bytes: &input[32..],
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyFinish {
    pub request_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateNotification {
    pub opcode: Opcode,
    pub request_id: u64,
    pub snapshot_version: u64,
    pub generation: u64,
}

impl UpdateNotification {
    pub const fn trust(request_id: u64, snapshot_version: u64, generation: u64) -> Self {
        Self {
            opcode: Opcode::TrustUpdated,
            request_id,
            snapshot_version,
            generation,
        }
    }

    pub const fn revocations(request_id: u64, snapshot_version: u64, generation: u64) -> Self {
        Self {
            opcode: Opcode::RevocationsUpdated,
            request_id,
            snapshot_version,
            generation,
        }
    }

    pub const fn opcode(&self) -> Opcode {
        self.opcode
    }

    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn encoded_len(&self) -> usize {
        UPDATE_NOTIFICATION_LEN
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        if !matches!(
            self.opcode,
            Opcode::TrustUpdated | Opcode::RevocationsUpdated
        ) {
            return Err(EncodeError::InvalidOpcode);
        }
        require(output, UPDATE_NOTIFICATION_LEN)?;
        write_header(output, self.opcode, self.request_id, 16);
        output[24..32].copy_from_slice(&self.snapshot_version.to_le_bytes());
        output[32..40].copy_from_slice(&self.generation.to_le_bytes());
        Ok(UPDATE_NOTIFICATION_LEN)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let header = decode_header(input)?;
        if !matches!(
            header.opcode,
            Opcode::TrustUpdated | Opcode::RevocationsUpdated
        ) {
            return Err(DecodeError::UnexpectedUpdateOpcode(header.opcode));
        }
        if header.payload_len != 16 || input.len() != UPDATE_NOTIFICATION_LEN {
            return Err(DecodeError::InvalidLength);
        }
        Ok(Self {
            opcode: header.opcode,
            request_id: header.request_id,
            snapshot_version: read_u64(input, 24),
            generation: read_u64(input, 32),
        })
    }
}

impl VerifyFinish {
    pub const fn opcode(&self) -> Opcode {
        Opcode::VerifyFinish
    }
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }
    pub const fn encoded_len(&self) -> usize {
        FINISH_LEN
    }
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        require(output, FINISH_LEN)?;
        write_header(output, self.opcode(), self.request_id, 0);
        Ok(FINISH_LEN)
    }
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let header = expected_header(input, Opcode::VerifyFinish)?;
        if header.payload_len != 0 {
            return Err(DecodeError::InvalidLength);
        }
        Ok(Self {
            request_id: header.request_id,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorResponse {
    pub request_id: u64,
    pub status: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusResponse {
    pub request_id: u64,
    pub status: i32,
}

impl StatusResponse {
    pub const fn opcode(&self) -> Opcode {
        Opcode::Status
    }
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }
    pub const fn encoded_len(&self) -> usize {
        ERROR_LEN
    }
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        require(output, ERROR_LEN)?;
        write_header(output, self.opcode(), self.request_id, 8);
        output[24..28].copy_from_slice(&self.status.to_le_bytes());
        output[28..32].fill(0);
        Ok(ERROR_LEN)
    }
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let header = expected_header(input, Opcode::Status)?;
        if input.len() != ERROR_LEN || input[28..32].iter().any(|byte| *byte != 0) {
            return Err(DecodeError::NonZeroReserved);
        }
        Ok(Self {
            request_id: header.request_id,
            status: read_i32(input, 24),
        })
    }
}

impl ErrorResponse {
    pub const fn opcode(&self) -> Opcode {
        Opcode::Error
    }
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }
    pub const fn encoded_len(&self) -> usize {
        ERROR_LEN
    }
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        require(output, ERROR_LEN)?;
        write_header(output, self.opcode(), self.request_id, 8);
        output[24..28].copy_from_slice(&self.status.to_le_bytes());
        output[28..32].fill(0);
        Ok(ERROR_LEN)
    }
    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let header = expected_header(input, Opcode::Error)?;
        if input.len() != ERROR_LEN || input[28..32].iter().any(|byte| *byte != 0) {
            return Err(DecodeError::NonZeroReserved);
        }
        Ok(Self {
            request_id: header.request_id,
            status: read_i32(input, 24),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedResponse<'a> {
    pub request_id: u64,
    pub certificate_serial: u64,
    pub subject_key_id: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub package_digest: [u8; 32],
    pub developer_id: &'a str,
    pub verified_package_id: &'a str,
    pub allowed_capabilities: &'a [&'a str],
}

impl VerifiedResponse<'_> {
    pub const fn opcode(&self) -> Opcode {
        Opcode::Verified
    }
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }
    pub fn encoded_len(&self) -> usize {
        VERIFIED_FIXED_LEN
            + self.developer_id.len()
            + self.verified_package_id.len()
            + self
                .allowed_capabilities
                .iter()
                .map(|value| 2 + value.len())
                .sum::<usize>()
    }
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        let developer_len =
            u16::try_from(self.developer_id.len()).map_err(|_| EncodeError::ValueTooLong)?;
        let package_len =
            u16::try_from(self.verified_package_id.len()).map_err(|_| EncodeError::ValueTooLong)?;
        let cap_count = u16::try_from(self.allowed_capabilities.len())
            .map_err(|_| EncodeError::TooManyCapabilities)?;
        for capability in self.allowed_capabilities {
            u16::try_from(capability.len()).map_err(|_| EncodeError::ValueTooLong)?;
        }
        let length = self.encoded_len();
        require(output, length)?;
        let payload_len =
            u32::try_from(length - HEADER_LEN).map_err(|_| EncodeError::ValueTooLong)?;
        write_header(output, self.opcode(), self.request_id, payload_len);
        output[24..32].copy_from_slice(&self.certificate_serial.to_le_bytes());
        output[32..64].copy_from_slice(&self.subject_key_id);
        output[64..96].copy_from_slice(&self.manifest_digest);
        output[96..128].copy_from_slice(&self.package_digest);
        output[128..130].copy_from_slice(&developer_len.to_le_bytes());
        output[130..132].copy_from_slice(&package_len.to_le_bytes());
        output[132..134].copy_from_slice(&cap_count.to_le_bytes());
        output[134..136].fill(0);
        let mut cursor = VERIFIED_FIXED_LEN;
        put_text(output, &mut cursor, self.developer_id);
        put_text(output, &mut cursor, self.verified_package_id);
        for capability in self.allowed_capabilities {
            let length = capability.len() as u16;
            output[cursor..cursor + 2].copy_from_slice(&length.to_le_bytes());
            cursor += 2;
            put_text(output, &mut cursor, capability);
        }
        Ok(cursor)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedView<'a> {
    pub request_id: u64,
    pub certificate_serial: u64,
    pub subject_key_id: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub package_digest: [u8; 32],
    pub developer_id: &'a str,
    pub verified_package_id: &'a str,
    capability_bytes: &'a [u8],
    capability_count: u16,
}

impl<'a> VerifiedView<'a> {
    pub const fn opcode(&self) -> Opcode {
        Opcode::Verified
    }
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }
    pub fn allowed_capabilities(&self) -> CapabilityIter<'a> {
        CapabilityIter {
            bytes: self.capability_bytes,
            remaining: self.capability_count,
        }
    }
    pub fn decode(input: &'a [u8]) -> Result<Self, DecodeError> {
        let header = expected_header(input, Opcode::Verified)?;
        if input.len() < VERIFIED_FIXED_LEN || input[134..136].iter().any(|byte| *byte != 0) {
            return Err(DecodeError::NonZeroReserved);
        }
        let developer_len = usize::from(read_u16(input, 128));
        let package_len = usize::from(read_u16(input, 130));
        let capability_count = read_u16(input, 132);
        let mut cursor = VERIFIED_FIXED_LEN;
        let developer_id = take_text(input, &mut cursor, developer_len)?;
        let verified_package_id = take_text(input, &mut cursor, package_len)?;
        validate_text(developer_id)?;
        validate_text(verified_package_id)?;
        let capability_bytes = &input[cursor..];
        let mut iterator = CapabilityIter {
            bytes: capability_bytes,
            remaining: capability_count,
        };
        while let Some(capability) = iterator.next() {
            validate_text(capability?)?;
        }
        if !iterator.bytes.is_empty() {
            return Err(DecodeError::InvalidCapabilityList);
        }
        let mut subject_key_id = [0; 32];
        subject_key_id.copy_from_slice(&input[32..64]);
        let mut manifest_digest = [0; 32];
        manifest_digest.copy_from_slice(&input[64..96]);
        let mut package_digest = [0; 32];
        package_digest.copy_from_slice(&input[96..128]);
        Ok(Self {
            request_id: header.request_id,
            certificate_serial: read_u64(input, 24),
            subject_key_id,
            manifest_digest,
            package_digest,
            developer_id,
            verified_package_id,
            capability_bytes,
            capability_count,
        })
    }
}

pub struct CapabilityIter<'a> {
    bytes: &'a [u8],
    remaining: u16,
}

impl<'a> Iterator for CapabilityIter<'a> {
    type Item = Result<&'a str, DecodeError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        if self.bytes.len() < 2 {
            self.remaining = 0;
            return Some(Err(DecodeError::InvalidCapabilityList));
        }
        let length = usize::from(read_u16(self.bytes, 0));
        if self.bytes.len() < 2 + length {
            self.remaining = 0;
            return Some(Err(DecodeError::InvalidCapabilityList));
        }
        let value =
            core::str::from_utf8(&self.bytes[2..2 + length]).map_err(|_| DecodeError::InvalidUtf8);
        self.bytes = &self.bytes[2 + length..];
        self.remaining -= 1;
        Some(value)
    }
}

pub fn decode_opcode(input: &[u8]) -> Result<Opcode, DecodeError> {
    Ok(decode_header(input)?.opcode)
}

fn decode_header(input: &[u8]) -> Result<Header, DecodeError> {
    if input.len() < HEADER_LEN {
        return Err(DecodeError::InvalidLength);
    }
    let magic = read_u32(input, 0);
    if magic != MAGIC {
        return Err(DecodeError::InvalidMagic(magic));
    }
    let version = read_u16(input, 4);
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let opcode = match read_u16(input, 6) {
        1 => Opcode::VerifyBegin,
        2 => Opcode::VerifyChunk,
        3 => Opcode::VerifyFinish,
        0x0100 => Opcode::TrustUpdated,
        0x0101 => Opcode::RevocationsUpdated,
        0x8000 => Opcode::Status,
        0x8003 => Opcode::Verified,
        0xffff => Opcode::Error,
        value => return Err(DecodeError::UnknownOpcode(value)),
    };
    let payload_len = read_u32(input, 16) as usize;
    if read_u32(input, 20) != 0 {
        return Err(DecodeError::NonZeroFlags(read_u32(input, 20)));
    }
    if input.len()
        != HEADER_LEN
            .checked_add(payload_len)
            .ok_or(DecodeError::InvalidLength)?
    {
        return Err(DecodeError::InvalidLength);
    }
    Ok(Header {
        opcode,
        request_id: read_u64(input, 8),
        payload_len,
    })
}
fn expected_header(input: &[u8], expected: Opcode) -> Result<Header, DecodeError> {
    let header = decode_header(input)?;
    if header.opcode != expected {
        return Err(DecodeError::UnexpectedOpcode {
            expected,
            actual: header.opcode,
        });
    }
    Ok(header)
}
fn write_header(output: &mut [u8], opcode: Opcode, request_id: u64, payload_len: u32) {
    output[..4].copy_from_slice(&MAGIC.to_le_bytes());
    output[4..6].copy_from_slice(&VERSION.to_le_bytes());
    output[6..8].copy_from_slice(&opcode.wire_value().to_le_bytes());
    output[8..16].copy_from_slice(&request_id.to_le_bytes());
    output[16..20].copy_from_slice(&payload_len.to_le_bytes());
    output[20..24].fill(0);
}
fn require(output: &[u8], required: usize) -> Result<(), EncodeError> {
    if output.len() < required {
        Err(EncodeError::BufferTooSmall {
            required,
            actual: output.len(),
        })
    } else {
        Ok(())
    }
}
fn put_text(output: &mut [u8], cursor: &mut usize, value: &str) {
    let end = *cursor + value.len();
    output[*cursor..end].copy_from_slice(value.as_bytes());
    *cursor = end;
}
fn take_text<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a str, DecodeError> {
    let end = cursor
        .checked_add(length)
        .ok_or(DecodeError::InvalidLength)?;
    let bytes = input.get(*cursor..end).ok_or(DecodeError::InvalidLength)?;
    *cursor = end;
    core::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8)
}
fn validate_text(value: &str) -> Result<(), DecodeError> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
    {
        Err(DecodeError::InvalidText)
    } else {
        Ok(())
    }
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
fn read_i32(input: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}
fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap_or([0; 8]))
}
