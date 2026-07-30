#![no_std]
#![deny(unsafe_code)]

use core::fmt;

use sha2::{Digest, Sha256};

pub const MAGIC: u32 = 0x494b_5043;
pub const FORMAT_VERSION: u16 = 1;
pub const MAX_ETAG_BYTES: usize = 128;
pub const CHECKSUM_LEN: usize = 32;
pub const STATE_LEN: usize = 392;

const CHECKSUM_OFFSET: usize = STATE_LEN - CHECKSUM_LEN;
const TRUST_ETAG_OFFSET: usize = 104;
const REVOCATION_ETAG_OFFSET: usize = TRUST_ETAG_OFFSET + MAX_ETAG_BYTES;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Slot {
    #[default]
    A = 0,
    B = 1,
}

impl Slot {
    pub const fn inactive(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    const fn decode(value: u8) -> Result<Self, DecodeError> {
        match value {
            0 => Ok(Self::A),
            1 => Ok(Self::B),
            _ => Err(DecodeError::InvalidSlot(value)),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Etag {
    bytes: [u8; MAX_ETAG_BYTES],
    len: u8,
}

impl Etag {
    pub const fn none() -> Self {
        Self {
            bytes: [0; MAX_ETAG_BYTES],
            len: 0,
        }
    }

    pub fn parse(value: &str) -> Result<Self, EtagError> {
        let bytes = value.as_bytes();
        if bytes.len() > MAX_ETAG_BYTES {
            return Err(EtagError::TooLong);
        }
        if !bytes.is_empty() && !valid_etag(bytes) {
            return Err(EtagError::Invalid);
        }
        let mut result = Self::none();
        result.bytes[..bytes.len()].copy_from_slice(bytes);
        result.len = bytes.len() as u8;
        Ok(result)
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).unwrap_or_default()
    }

    pub const fn is_none(&self) -> bool {
        self.len == 0
    }
}

impl Default for Etag {
    fn default() -> Self {
        Self::none()
    }
}

impl fmt::Debug for Etag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Etag").field(&self.as_str()).finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EtagError {
    TooLong,
    Invalid,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnapshotMetadata {
    pub snapshot_version: u64,
    pub generated_at: u64,
    pub expires_at: u64,
    pub last_checked_at: u64,
    pub etag: Etag,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DatabaseState {
    pub generation: u64,
    pub active_trust_slot: Slot,
    pub active_revocation_slot: Slot,
    pub trust: SnapshotMetadata,
    pub revocations: SnapshotMetadata,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    BufferTooSmall { required: usize, actual: usize },
    InvalidEtag,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    InvalidLength { expected: usize, actual: usize },
    InvalidMagic(u32),
    UnsupportedVersion(u16),
    InvalidEncodedLength(u16),
    InvalidSlot(u8),
    NonZeroReserved,
    InvalidEtagLength(u16),
    InvalidEtag,
    ChecksumMismatch,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "{self:?}")
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "{self:?}")
    }
}

impl DatabaseState {
    pub const fn encoded_len(&self) -> usize {
        STATE_LEN
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        if output.len() < STATE_LEN {
            return Err(EncodeError::BufferTooSmall {
                required: STATE_LEN,
                actual: output.len(),
            });
        }
        if !valid_stored_etag(&self.trust.etag) || !valid_stored_etag(&self.revocations.etag) {
            return Err(EncodeError::InvalidEtag);
        }
        let bytes = &mut output[..STATE_LEN];
        bytes.fill(0);
        write_u32(bytes, 0, MAGIC);
        write_u16(bytes, 4, FORMAT_VERSION);
        write_u16(bytes, 6, STATE_LEN as u16);
        write_u64(bytes, 8, self.generation);
        bytes[16] = self.active_trust_slot as u8;
        bytes[17] = self.active_revocation_slot as u8;
        encode_metadata(bytes, 24, 56, TRUST_ETAG_OFFSET, &self.trust);
        encode_metadata(bytes, 64, 96, REVOCATION_ETAG_OFFSET, &self.revocations);
        let checksum = Sha256::digest(&bytes[..CHECKSUM_OFFSET]);
        bytes[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        Ok(STATE_LEN)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        if input.len() != STATE_LEN {
            return Err(DecodeError::InvalidLength {
                expected: STATE_LEN,
                actual: input.len(),
            });
        }
        let magic = read_u32(input, 0);
        if magic != MAGIC {
            return Err(DecodeError::InvalidMagic(magic));
        }
        let version = read_u16(input, 4);
        if version != FORMAT_VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        let encoded_length = read_u16(input, 6);
        if usize::from(encoded_length) != STATE_LEN {
            return Err(DecodeError::InvalidEncodedLength(encoded_length));
        }
        if input[18..24].iter().any(|byte| *byte != 0)
            || input[58..64].iter().any(|byte| *byte != 0)
            || input[98..104].iter().any(|byte| *byte != 0)
        {
            return Err(DecodeError::NonZeroReserved);
        }
        let state = Self {
            generation: read_u64(input, 8),
            active_trust_slot: Slot::decode(input[16])?,
            active_revocation_slot: Slot::decode(input[17])?,
            trust: decode_metadata(input, 24, 56, TRUST_ETAG_OFFSET)?,
            revocations: decode_metadata(input, 64, 96, REVOCATION_ETAG_OFFSET)?,
        };
        let checksum = Sha256::digest(&input[..CHECKSUM_OFFSET]);
        if input[CHECKSUM_OFFSET..] != checksum[..] {
            return Err(DecodeError::ChecksumMismatch);
        }
        Ok(state)
    }
}

fn encode_metadata(
    output: &mut [u8],
    values_offset: usize,
    length_offset: usize,
    etag_offset: usize,
    metadata: &SnapshotMetadata,
) {
    write_u64(output, values_offset, metadata.snapshot_version);
    write_u64(output, values_offset + 8, metadata.generated_at);
    write_u64(output, values_offset + 16, metadata.expires_at);
    write_u64(output, values_offset + 24, metadata.last_checked_at);
    write_u16(output, length_offset, u16::from(metadata.etag.len));
    let length = usize::from(metadata.etag.len);
    output[etag_offset..etag_offset + length].copy_from_slice(&metadata.etag.bytes[..length]);
}

fn decode_metadata(
    input: &[u8],
    values_offset: usize,
    length_offset: usize,
    etag_offset: usize,
) -> Result<SnapshotMetadata, DecodeError> {
    let length = read_u16(input, length_offset);
    if usize::from(length) > MAX_ETAG_BYTES {
        return Err(DecodeError::InvalidEtagLength(length));
    }
    let length = usize::from(length);
    let etag_bytes = &input[etag_offset..etag_offset + MAX_ETAG_BYTES];
    if etag_bytes[length..].iter().any(|byte| *byte != 0) {
        return Err(DecodeError::NonZeroReserved);
    }
    let etag_text =
        core::str::from_utf8(&etag_bytes[..length]).map_err(|_| DecodeError::InvalidEtag)?;
    let etag = Etag::parse(etag_text).map_err(|_| DecodeError::InvalidEtag)?;
    Ok(SnapshotMetadata {
        snapshot_version: read_u64(input, values_offset),
        generated_at: read_u64(input, values_offset + 8),
        expires_at: read_u64(input, values_offset + 16),
        last_checked_at: read_u64(input, values_offset + 24),
        etag,
    })
}

fn valid_stored_etag(etag: &Etag) -> bool {
    let length = usize::from(etag.len);
    length <= MAX_ETAG_BYTES
        && etag.bytes[length..].iter().all(|byte| *byte == 0)
        && (length == 0 || valid_etag(&etag.bytes[..length]))
}

fn valid_etag(bytes: &[u8]) -> bool {
    let opaque = if bytes.starts_with(b"W/\"") && bytes.ends_with(b"\"") {
        &bytes[3..bytes.len().saturating_sub(1)]
    } else if bytes.starts_with(b"\"") && bytes.ends_with(b"\"") {
        &bytes[1..bytes.len().saturating_sub(1)]
    } else {
        return false;
    };
    opaque
        .iter()
        .all(|byte| *byte == 0x21 || (0x23..=0x7e).contains(byte))
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
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
