#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt;
#[cfg(feature = "alloc")]
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const MAGIC: [u8; 4] = *b"MCER";
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 144;
pub const SIGNATURE_LEN: usize = 64;
pub const DOMAIN_SEPARATOR: &[u8] = b"mochios-certificate-v1\0";
pub const KEY_USAGE_PACKAGE_SIGNING: u32 = 1;
pub const MAX_CERTIFICATE_LEN: usize = 1024 * 1024;
pub const MAX_DEVELOPER_ID_LEN: usize = 32;
pub const MAX_PACKAGE_SCOPES: usize = 256;
pub const MAX_ALLOWED_CAPABILITIES: usize = 512;
pub const MAX_ITEM_LEN: usize = 255;

#[cfg(feature = "alloc")]
const OFFSET_TOTAL_LEN: usize = 8;
#[cfg(feature = "alloc")]
const OFFSET_SERIAL: usize = 12;
#[cfg(feature = "alloc")]
const OFFSET_ISSUER_KEY_ID: usize = 20;
#[cfg(feature = "alloc")]
const OFFSET_SUBJECT_KEY_ID: usize = 52;
#[cfg(feature = "alloc")]
const OFFSET_SUBJECT_PUBLIC_KEY: usize = 84;
#[cfg(feature = "alloc")]
const OFFSET_NOT_BEFORE: usize = 116;
#[cfg(feature = "alloc")]
const OFFSET_NOT_AFTER: usize = 124;
#[cfg(feature = "alloc")]
const OFFSET_KEY_USAGE: usize = 132;
#[cfg(feature = "alloc")]
const OFFSET_DEVELOPER_ID_LEN: usize = 136;
#[cfg(feature = "alloc")]
const OFFSET_SCOPE_COUNT: usize = 138;
#[cfg(feature = "alloc")]
const OFFSET_CAPABILITY_COUNT: usize = 140;
#[cfg(feature = "alloc")]
const OFFSET_RESERVED: usize = 142;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PackageScopeKind {
    Exact = 1,
    Prefix = 2,
}

impl PackageScopeKind {
    #[cfg(feature = "alloc")]
    fn decode(value: u8) -> Result<Self, DecodeError> {
        match value {
            1 => Ok(Self::Exact),
            2 => Ok(Self::Prefix),
            _ => Err(DecodeError::UnknownScopeKind { actual: value }),
        }
    }
}

#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageIdScope {
    pub kind: PackageScopeKind,
    pub package_id: String,
}

#[cfg(feature = "alloc")]
impl PackageIdScope {
    pub fn exact(package_id: impl Into<String>) -> Self {
        Self {
            kind: PackageScopeKind::Exact,
            package_id: package_id.into(),
        }
    }

    pub fn prefix(package_id: impl Into<String>) -> Self {
        Self {
            kind: PackageScopeKind::Prefix,
            package_id: package_id.into(),
        }
    }

    pub fn matches(&self, package_id: &str) -> bool {
        match self.kind {
            PackageScopeKind::Exact => self.package_id == package_id,
            PackageScopeKind::Prefix => {
                package_id == self.package_id
                    || package_id
                        .strip_prefix(self.package_id.as_str())
                        .is_some_and(|suffix| suffix.starts_with('.'))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    BufferTooSmall { required: usize, actual: usize },
    LengthOverflow,
    InvalidCertificate(ValidationError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationError {
    ZeroSerialNumber,
    InvalidDeveloperId,
    InvalidSubjectPublicKey,
    SubjectKeyIdMismatch,
    InvalidValidityRange,
    UnknownKeyUsage { actual: u32 },
    MissingPackageScope,
    TooManyPackageScopes,
    InvalidPackageScope,
    UnsortedPackageScopes,
    DuplicatePackageScope,
    TooManyAllowedCapabilities,
    InvalidCapability,
    UnsortedAllowedCapabilities,
    DuplicateAllowedCapability,
    CertificateTooLarge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    TooShort { minimum: usize, actual: usize },
    InvalidLength { expected: usize, actual: usize },
    InvalidMagic { actual: [u8; 4] },
    UnsupportedVersion { actual: u16 },
    InvalidHeaderLength { actual: u16 },
    NonZeroReserved { offset: usize, actual: u64 },
    InvalidUtf8 { offset: usize },
    UnknownScopeKind { actual: u8 },
    Validation(ValidationError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifyError {
    InvalidRootPublicKey,
    IssuerKeyIdMismatch,
    NotYetValid,
    Expired,
    PackageIdNotAllowed,
    InvalidSignature,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid developer certificate: {self:?}")
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "developer certificate decode failed: {self:?}")
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "developer certificate encode failed: {self:?}")
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "developer certificate verification failed: {self:?}")
    }
}

#[cfg(feature = "alloc")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeveloperCertificate {
    pub serial_number: u64,
    pub issuer_key_id: [u8; 32],
    pub developer_id: String,
    pub subject_key_id: [u8; 32],
    pub subject_public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub key_usage: u32,
    pub package_id_scopes: Vec<PackageIdScope>,
    pub allowed_capabilities: Vec<String>,
    pub signature: [u8; SIGNATURE_LEN],
}

#[cfg(feature = "alloc")]
impl DeveloperCertificate {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.serial_number == 0 {
            return Err(ValidationError::ZeroSerialNumber);
        }
        if !is_valid_developer_id(&self.developer_id) {
            return Err(ValidationError::InvalidDeveloperId);
        }
        if VerifyingKey::from_bytes(&self.subject_public_key).is_err() {
            return Err(ValidationError::InvalidSubjectPublicKey);
        }
        if key_id(&self.subject_public_key) != self.subject_key_id {
            return Err(ValidationError::SubjectKeyIdMismatch);
        }
        if self.not_before >= self.not_after {
            return Err(ValidationError::InvalidValidityRange);
        }
        if self.key_usage != KEY_USAGE_PACKAGE_SIGNING {
            return Err(ValidationError::UnknownKeyUsage {
                actual: self.key_usage,
            });
        }
        validate_scopes(&self.package_id_scopes)?;
        validate_capabilities(&self.allowed_capabilities)?;
        if self.encoded_len()? > MAX_CERTIFICATE_LEN {
            return Err(ValidationError::CertificateTooLarge);
        }
        Ok(())
    }

    pub fn encoded_len(&self) -> Result<usize, ValidationError> {
        let mut length = HEADER_LEN
            .checked_add(self.developer_id.len())
            .and_then(|value| value.checked_add(SIGNATURE_LEN))
            .ok_or(ValidationError::CertificateTooLarge)?;
        for scope in &self.package_id_scopes {
            length = length
                .checked_add(4)
                .and_then(|value| value.checked_add(scope.package_id.len()))
                .ok_or(ValidationError::CertificateTooLarge)?;
        }
        for capability in &self.allowed_capabilities {
            length = length
                .checked_add(2)
                .and_then(|value| value.checked_add(capability.len()))
                .ok_or(ValidationError::CertificateTooLarge)?;
        }
        Ok(length)
    }

    pub fn unsigned_encoded_len(&self) -> Result<usize, ValidationError> {
        self.encoded_len()?
            .checked_sub(SIGNATURE_LEN)
            .ok_or(ValidationError::CertificateTooLarge)
    }

    pub fn encode(&self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        self.validate().map_err(EncodeError::InvalidCertificate)?;
        let required = self
            .encoded_len()
            .map_err(EncodeError::InvalidCertificate)?;
        if buffer.len() < required {
            return Err(EncodeError::BufferTooSmall {
                required,
                actual: buffer.len(),
            });
        }
        self.encode_prefix(&mut buffer[..required - SIGNATURE_LEN], required)?;
        buffer[required - SIGNATURE_LEN..required].copy_from_slice(&self.signature);
        Ok(required)
    }

    pub fn signing_message(&self) -> Result<Vec<u8>, EncodeError> {
        self.validate().map_err(EncodeError::InvalidCertificate)?;
        let total_len = self
            .encoded_len()
            .map_err(EncodeError::InvalidCertificate)?;
        let unsigned_len = total_len - SIGNATURE_LEN;
        let capacity = DOMAIN_SEPARATOR
            .len()
            .checked_add(unsigned_len)
            .ok_or(EncodeError::LengthOverflow)?;
        let mut message = Vec::with_capacity(capacity);
        message.extend_from_slice(DOMAIN_SEPARATOR);
        message.resize(capacity, 0);
        self.encode_prefix(&mut message[DOMAIN_SEPARATOR.len()..], total_len)?;
        Ok(message)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < HEADER_LEN + SIGNATURE_LEN {
            return Err(DecodeError::TooShort {
                minimum: HEADER_LEN + SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        if bytes.len() > MAX_CERTIFICATE_LEN {
            return Err(DecodeError::Validation(
                ValidationError::CertificateTooLarge,
            ));
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[..4]);
        if magic != MAGIC {
            return Err(DecodeError::InvalidMagic { actual: magic });
        }
        let version = read_u16(bytes, 4);
        if version != FORMAT_VERSION {
            return Err(DecodeError::UnsupportedVersion { actual: version });
        }
        let header_len = read_u16(bytes, 6);
        if usize::from(header_len) != HEADER_LEN {
            return Err(DecodeError::InvalidHeaderLength { actual: header_len });
        }
        let total_len = read_u32(bytes, OFFSET_TOTAL_LEN) as usize;
        if total_len != bytes.len() {
            return Err(DecodeError::InvalidLength {
                expected: total_len,
                actual: bytes.len(),
            });
        }
        let reserved = read_u16(bytes, OFFSET_RESERVED);
        if reserved != 0 {
            return Err(DecodeError::NonZeroReserved {
                offset: OFFSET_RESERVED,
                actual: u64::from(reserved),
            });
        }
        let developer_len = usize::from(read_u16(bytes, OFFSET_DEVELOPER_ID_LEN));
        let scope_count = usize::from(read_u16(bytes, OFFSET_SCOPE_COUNT));
        let capability_count = usize::from(read_u16(bytes, OFFSET_CAPABILITY_COUNT));
        if scope_count > MAX_PACKAGE_SCOPES {
            return Err(DecodeError::Validation(
                ValidationError::TooManyPackageScopes,
            ));
        }
        if capability_count > MAX_ALLOWED_CAPABILITIES {
            return Err(DecodeError::Validation(
                ValidationError::TooManyAllowedCapabilities,
            ));
        }

        let body_end = bytes.len() - SIGNATURE_LEN;
        let mut cursor = HEADER_LEN;
        let developer_bytes = take(bytes, &mut cursor, developer_len, body_end)?;
        let developer_id = core::str::from_utf8(developer_bytes)
            .map_err(|_| DecodeError::InvalidUtf8 { offset: HEADER_LEN })?
            .to_string();

        let mut package_id_scopes = Vec::with_capacity(scope_count);
        for _ in 0..scope_count {
            let header = take(bytes, &mut cursor, 4, body_end)?;
            let kind = PackageScopeKind::decode(header[0])?;
            if header[1] != 0 {
                return Err(DecodeError::NonZeroReserved {
                    offset: cursor - 3,
                    actual: u64::from(header[1]),
                });
            }
            let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
            let offset = cursor;
            let value = take(bytes, &mut cursor, length, body_end)?;
            let package_id = core::str::from_utf8(value)
                .map_err(|_| DecodeError::InvalidUtf8 { offset })?
                .to_string();
            package_id_scopes.push(PackageIdScope { kind, package_id });
        }

        let mut allowed_capabilities = Vec::with_capacity(capability_count);
        for _ in 0..capability_count {
            let length_bytes = take(bytes, &mut cursor, 2, body_end)?;
            let length = usize::from(u16::from_le_bytes([length_bytes[0], length_bytes[1]]));
            let offset = cursor;
            let value = take(bytes, &mut cursor, length, body_end)?;
            let capability = core::str::from_utf8(value)
                .map_err(|_| DecodeError::InvalidUtf8 { offset })?
                .to_string();
            allowed_capabilities.push(capability);
        }
        if cursor != body_end {
            return Err(DecodeError::InvalidLength {
                expected: cursor + SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }

        let mut issuer_key_id = [0u8; 32];
        issuer_key_id.copy_from_slice(&bytes[OFFSET_ISSUER_KEY_ID..OFFSET_SUBJECT_KEY_ID]);
        let mut subject_key_id = [0u8; 32];
        subject_key_id.copy_from_slice(&bytes[OFFSET_SUBJECT_KEY_ID..OFFSET_SUBJECT_PUBLIC_KEY]);
        let mut subject_public_key = [0u8; 32];
        subject_public_key.copy_from_slice(&bytes[OFFSET_SUBJECT_PUBLIC_KEY..OFFSET_NOT_BEFORE]);
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[body_end..]);
        let certificate = Self {
            serial_number: read_u64(bytes, OFFSET_SERIAL),
            issuer_key_id,
            developer_id,
            subject_key_id,
            subject_public_key,
            not_before: read_u64(bytes, OFFSET_NOT_BEFORE),
            not_after: read_u64(bytes, OFFSET_NOT_AFTER),
            key_usage: read_u32(bytes, OFFSET_KEY_USAGE),
            package_id_scopes,
            allowed_capabilities,
            signature,
        };
        certificate.validate().map_err(DecodeError::Validation)?;
        Ok(certificate)
    }

    pub fn verify(
        &self,
        root_public_key: &[u8; 32],
        unix_time: u64,
        package_id: &str,
    ) -> Result<VerifiedDeveloper<'_>, VerifyError> {
        let verifier = VerifyingKey::from_bytes(root_public_key)
            .map_err(|_| VerifyError::InvalidRootPublicKey)?;
        if key_id(root_public_key) != self.issuer_key_id {
            return Err(VerifyError::IssuerKeyIdMismatch);
        }
        let message = self
            .signing_message()
            .map_err(|_| VerifyError::InvalidSignature)?;
        verifier
            .verify_strict(&message, &Signature::from_bytes(&self.signature))
            .map_err(|_| VerifyError::InvalidSignature)?;
        if unix_time < self.not_before {
            return Err(VerifyError::NotYetValid);
        }
        if unix_time >= self.not_after {
            return Err(VerifyError::Expired);
        }
        if !is_valid_package_id(package_id)
            || !self
                .package_id_scopes
                .iter()
                .any(|scope| scope.matches(package_id))
        {
            return Err(VerifyError::PackageIdNotAllowed);
        }
        Ok(VerifiedDeveloper { certificate: self })
    }

    fn encode_prefix(&self, buffer: &mut [u8], total_len: usize) -> Result<(), EncodeError> {
        let total_len = u32::try_from(total_len).map_err(|_| EncodeError::LengthOverflow)?;
        let developer_len =
            u16::try_from(self.developer_id.len()).map_err(|_| EncodeError::LengthOverflow)?;
        let scope_count =
            u16::try_from(self.package_id_scopes.len()).map_err(|_| EncodeError::LengthOverflow)?;
        let capability_count = u16::try_from(self.allowed_capabilities.len())
            .map_err(|_| EncodeError::LengthOverflow)?;
        buffer[..4].copy_from_slice(&MAGIC);
        write_u16(buffer, 4, FORMAT_VERSION);
        write_u16(buffer, 6, HEADER_LEN as u16);
        write_u32(buffer, OFFSET_TOTAL_LEN, total_len);
        write_u64(buffer, OFFSET_SERIAL, self.serial_number);
        buffer[OFFSET_ISSUER_KEY_ID..OFFSET_SUBJECT_KEY_ID].copy_from_slice(&self.issuer_key_id);
        buffer[OFFSET_SUBJECT_KEY_ID..OFFSET_SUBJECT_PUBLIC_KEY]
            .copy_from_slice(&self.subject_key_id);
        buffer[OFFSET_SUBJECT_PUBLIC_KEY..OFFSET_NOT_BEFORE]
            .copy_from_slice(&self.subject_public_key);
        write_u64(buffer, OFFSET_NOT_BEFORE, self.not_before);
        write_u64(buffer, OFFSET_NOT_AFTER, self.not_after);
        write_u32(buffer, OFFSET_KEY_USAGE, self.key_usage);
        write_u16(buffer, OFFSET_DEVELOPER_ID_LEN, developer_len);
        write_u16(buffer, OFFSET_SCOPE_COUNT, scope_count);
        write_u16(buffer, OFFSET_CAPABILITY_COUNT, capability_count);
        write_u16(buffer, OFFSET_RESERVED, 0);
        let mut cursor = HEADER_LEN;
        write_bytes(buffer, &mut cursor, self.developer_id.as_bytes())?;
        for scope in &self.package_id_scopes {
            let length =
                u16::try_from(scope.package_id.len()).map_err(|_| EncodeError::LengthOverflow)?;
            write_bytes(buffer, &mut cursor, &[scope.kind as u8, 0])?;
            write_bytes(buffer, &mut cursor, &length.to_le_bytes())?;
            write_bytes(buffer, &mut cursor, scope.package_id.as_bytes())?;
        }
        for capability in &self.allowed_capabilities {
            let length =
                u16::try_from(capability.len()).map_err(|_| EncodeError::LengthOverflow)?;
            write_bytes(buffer, &mut cursor, &length.to_le_bytes())?;
            write_bytes(buffer, &mut cursor, capability.as_bytes())?;
        }
        if cursor != buffer.len() {
            return Err(EncodeError::LengthOverflow);
        }
        Ok(())
    }
}

#[cfg(feature = "alloc")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedDeveloper<'a> {
    certificate: &'a DeveloperCertificate,
}

#[cfg(feature = "alloc")]
impl<'a> VerifiedDeveloper<'a> {
    pub const fn certificate(&self) -> &'a DeveloperCertificate {
        self.certificate
    }

    pub fn allows_capability(&self, capability: &str) -> bool {
        self.certificate
            .allowed_capabilities
            .binary_search_by(|entry| entry.as_str().cmp(capability))
            .is_ok()
    }
}

pub fn key_id(public_key: &[u8; 32]) -> [u8; 32] {
    let digest = Sha256::digest(public_key);
    let mut result = [0u8; 32];
    result.copy_from_slice(&digest);
    result
}

pub fn is_valid_developer_id(value: &str) -> bool {
    value.len() == MAX_DEVELOPER_ID_LEN
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        && value.as_bytes()[12] == b'7'
        && matches!(value.as_bytes()[16], b'8' | b'9' | b'a' | b'b')
}

pub fn is_valid_package_id(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_ITEM_LEN {
        return false;
    }
    let mut segments = value.split('.');
    let Some(first) = segments.next() else {
        return false;
    };
    valid_package_segment(first)
        && segments
            .try_fold(0usize, |count, segment| {
                valid_package_segment(segment).then_some(count + 1)
            })
            .is_some_and(|separator_count| separator_count >= 1)
}

fn valid_package_segment(segment: &str) -> bool {
    !segment.is_empty()
        && !segment.starts_with('-')
        && !segment.ends_with('-')
        && segment
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

pub fn is_valid_capability(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ITEM_LEN
        && value
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_'))
}

#[cfg(feature = "alloc")]
fn validate_scopes(scopes: &[PackageIdScope]) -> Result<(), ValidationError> {
    if scopes.is_empty() {
        return Err(ValidationError::MissingPackageScope);
    }
    if scopes.len() > MAX_PACKAGE_SCOPES {
        return Err(ValidationError::TooManyPackageScopes);
    }
    let mut previous: Option<&PackageIdScope> = None;
    for scope in scopes {
        if !is_valid_package_id(&scope.package_id) {
            return Err(ValidationError::InvalidPackageScope);
        }
        if let Some(previous) = previous {
            if previous == scope {
                return Err(ValidationError::DuplicatePackageScope);
            }
            if previous > scope {
                return Err(ValidationError::UnsortedPackageScopes);
            }
        }
        previous = Some(scope);
    }
    Ok(())
}

#[cfg(feature = "alloc")]
fn validate_capabilities(capabilities: &[String]) -> Result<(), ValidationError> {
    if capabilities.len() > MAX_ALLOWED_CAPABILITIES {
        return Err(ValidationError::TooManyAllowedCapabilities);
    }
    let mut previous: Option<&str> = None;
    for capability in capabilities {
        if !is_valid_capability(capability) {
            return Err(ValidationError::InvalidCapability);
        }
        if let Some(previous) = previous {
            if previous == capability {
                return Err(ValidationError::DuplicateAllowedCapability);
            }
            if previous > capability.as_str() {
                return Err(ValidationError::UnsortedAllowedCapabilities);
            }
        }
        previous = Some(capability);
    }
    Ok(())
}

#[cfg(feature = "alloc")]
fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
    limit: usize,
) -> Result<&'a [u8], DecodeError> {
    let end = cursor
        .checked_add(length)
        .ok_or(DecodeError::InvalidLength {
            expected: usize::MAX,
            actual: bytes.len(),
        })?;
    if end > limit {
        return Err(DecodeError::TooShort {
            minimum: end + SIGNATURE_LEN,
            actual: bytes.len(),
        });
    }
    let result = &bytes[*cursor..end];
    *cursor = end;
    Ok(result)
}

#[cfg(feature = "alloc")]
fn write_bytes(buffer: &mut [u8], cursor: &mut usize, bytes: &[u8]) -> Result<(), EncodeError> {
    let actual = buffer.len();
    let end = cursor
        .checked_add(bytes.len())
        .ok_or(EncodeError::LengthOverflow)?;
    let target = buffer
        .get_mut(*cursor..end)
        .ok_or(EncodeError::BufferTooSmall {
            required: end,
            actual,
        })?;
    target.copy_from_slice(bytes);
    *cursor = end;
    Ok(())
}

#[cfg(feature = "alloc")]
fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

#[cfg(feature = "alloc")]
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(feature = "alloc")]
fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

#[cfg(feature = "alloc")]
fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "alloc")]
fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(feature = "alloc")]
fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
