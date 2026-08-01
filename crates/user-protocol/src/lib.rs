#![no_std]

use core::fmt;

pub const MAGIC: u32 = 0x5253_554d;
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 24;
pub const SNAPSHOT_REQUEST_LEN: usize = HEADER_LEN;
pub const SNAPSHOT_INFO_LEN: usize = HEADER_LEN + 16;
pub const CHUNK_REQUEST_LEN: usize = HEADER_LEN + 16;
pub const CHUNK_RESPONSE_PREFIX_LEN: usize = HEADER_LEN + 16;
pub const STATUS_LEN: usize = HEADER_LEN + 16;
pub const MAX_MESSAGE_LEN: usize = 4_128;
pub const MAX_CHUNK_LEN: usize = MAX_MESSAGE_LEN - CHUNK_RESPONSE_PREFIX_LEN;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opcode {
    SnapshotBegin = 0x0001,
    SnapshotChunk = 0x0002,
    AddUser = 0x0010,
    RemoveUser = 0x0011,
    SnapshotInfo = 0x8001,
    SnapshotData = 0x8002,
    Status = 0x8000,
}

impl Opcode {
    pub const fn wire_value(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    BufferTooSmall { required: usize, actual: usize },
    ValueTooLong,
    InvalidLength,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    InvalidLength,
    InvalidMagic(u32),
    UnsupportedVersion(u16),
    UnknownOpcode(u16),
    UnexpectedOpcode { expected: Opcode, actual: Opcode },
    NonZeroFlags(u32),
    NonZeroReserved,
    InvalidUtf8,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(output, "{self:?}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub opcode: Opcode,
    pub request_id: u64,
    pub payload_len: usize,
}

pub fn decode_opcode(input: &[u8]) -> Result<Opcode, DecodeError> {
    Ok(decode_header(input)?.opcode)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotRequest {
    pub request_id: u64,
}

impl SnapshotRequest {
    pub const fn opcode(&self) -> Opcode {
        Opcode::SnapshotBegin
    }

    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn encoded_len(&self) -> usize {
        SNAPSHOT_REQUEST_LEN
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        require_output(output, SNAPSHOT_REQUEST_LEN)?;
        write_header(output, self.opcode(), self.request_id, 0);
        Ok(SNAPSHOT_REQUEST_LEN)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let header = expected_header(input, Opcode::SnapshotBegin)?;
        if header.payload_len != 0 {
            return Err(DecodeError::InvalidLength);
        }
        Ok(Self {
            request_id: header.request_id,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotInfo {
    pub request_id: u64,
    pub total_len: u64,
    pub generation: u64,
}

impl SnapshotInfo {
    pub const fn opcode(&self) -> Opcode {
        Opcode::SnapshotInfo
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        require_output(output, SNAPSHOT_INFO_LEN)?;
        write_header(output, self.opcode(), self.request_id, 16);
        write_u64(output, 24, self.total_len);
        write_u64(output, 32, self.generation);
        Ok(SNAPSHOT_INFO_LEN)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let header = expected_header(input, Opcode::SnapshotInfo)?;
        if header.payload_len != 16 {
            return Err(DecodeError::InvalidLength);
        }
        Ok(Self {
            request_id: header.request_id,
            total_len: read_u64(input, 24),
            generation: read_u64(input, 32),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotChunkRequest {
    pub request_id: u64,
    pub offset: u64,
    pub length: u32,
}

impl SnapshotChunkRequest {
    pub const fn opcode(&self) -> Opcode {
        Opcode::SnapshotChunk
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        if self.length == 0 || self.length as usize > MAX_CHUNK_LEN {
            return Err(EncodeError::InvalidLength);
        }
        require_output(output, CHUNK_REQUEST_LEN)?;
        write_header(output, self.opcode(), self.request_id, 16);
        write_u64(output, 24, self.offset);
        write_u32(output, 32, self.length);
        write_u32(output, 36, 0);
        Ok(CHUNK_REQUEST_LEN)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let header = expected_header(input, Opcode::SnapshotChunk)?;
        if header.payload_len != 16 || read_u32(input, 36) != 0 {
            return Err(if header.payload_len == 16 {
                DecodeError::NonZeroReserved
            } else {
                DecodeError::InvalidLength
            });
        }
        let length = read_u32(input, 32);
        if length == 0 || length as usize > MAX_CHUNK_LEN {
            return Err(DecodeError::InvalidLength);
        }
        Ok(Self {
            request_id: header.request_id,
            offset: read_u64(input, 24),
            length,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotChunk<'a> {
    pub request_id: u64,
    pub offset: u64,
    pub generation: u64,
    pub bytes: &'a [u8],
}

impl<'a> SnapshotChunk<'a> {
    pub const fn opcode(&self) -> Opcode {
        Opcode::SnapshotData
    }

    pub const fn encoded_len(&self) -> usize {
        CHUNK_RESPONSE_PREFIX_LEN + self.bytes.len()
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        if self.bytes.is_empty() || self.bytes.len() > MAX_CHUNK_LEN {
            return Err(EncodeError::InvalidLength);
        }
        let length = self.encoded_len();
        require_output(output, length)?;
        let payload_len =
            u32::try_from(16 + self.bytes.len()).map_err(|_| EncodeError::ValueTooLong)?;
        write_header(output, self.opcode(), self.request_id, payload_len);
        write_u64(output, 24, self.offset);
        write_u64(output, 32, self.generation);
        output[40..length].copy_from_slice(self.bytes);
        Ok(length)
    }

    pub fn decode(input: &'a [u8]) -> Result<Self, DecodeError> {
        let header = expected_header(input, Opcode::SnapshotData)?;
        if header.payload_len <= 16 || input.len() > MAX_MESSAGE_LEN {
            return Err(DecodeError::InvalidLength);
        }
        Ok(Self {
            request_id: header.request_id,
            offset: read_u64(input, 24),
            generation: read_u64(input, 32),
            bytes: &input[40..],
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddUser<'a> {
    pub request_id: u64,
    pub encoded_record: &'a [u8],
}

impl<'a> AddUser<'a> {
    pub const fn opcode(&self) -> Opcode {
        Opcode::AddUser
    }

    pub const fn encoded_len(&self) -> usize {
        HEADER_LEN + self.encoded_record.len()
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_bytes_message(output, self.opcode(), self.request_id, self.encoded_record)
    }

    pub fn decode(input: &'a [u8]) -> Result<Self, DecodeError> {
        let header = expected_header(input, Opcode::AddUser)?;
        if header.payload_len == 0 {
            return Err(DecodeError::InvalidLength);
        }
        Ok(Self {
            request_id: header.request_id,
            encoded_record: &input[HEADER_LEN..],
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemoveUser<'a> {
    pub request_id: u64,
    pub name: &'a str,
}

impl<'a> RemoveUser<'a> {
    pub const fn opcode(&self) -> Opcode {
        Opcode::RemoveUser
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        encode_bytes_message(output, self.opcode(), self.request_id, self.name.as_bytes())
    }

    pub fn decode(input: &'a [u8]) -> Result<Self, DecodeError> {
        let header = expected_header(input, Opcode::RemoveUser)?;
        if header.payload_len == 0 {
            return Err(DecodeError::InvalidLength);
        }
        let name =
            core::str::from_utf8(&input[HEADER_LEN..]).map_err(|_| DecodeError::InvalidUtf8)?;
        Ok(Self {
            request_id: header.request_id,
            name,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub request_id: u64,
    pub status: i32,
    pub generation: u64,
}

impl Status {
    pub const fn opcode(&self) -> Opcode {
        Opcode::Status
    }

    pub fn encode(&self, output: &mut [u8]) -> Result<usize, EncodeError> {
        require_output(output, STATUS_LEN)?;
        write_header(output, self.opcode(), self.request_id, 16);
        output[24..28].copy_from_slice(&self.status.to_le_bytes());
        write_u32(output, 28, 0);
        write_u64(output, 32, self.generation);
        Ok(STATUS_LEN)
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        let header = expected_header(input, Opcode::Status)?;
        if header.payload_len != 16 {
            return Err(DecodeError::InvalidLength);
        }
        if read_u32(input, 28) != 0 {
            return Err(DecodeError::NonZeroReserved);
        }
        Ok(Self {
            request_id: header.request_id,
            status: i32::from_le_bytes(input[24..28].try_into().unwrap_or([0; 4])),
            generation: read_u64(input, 32),
        })
    }
}

fn encode_bytes_message(
    output: &mut [u8],
    opcode: Opcode,
    request_id: u64,
    bytes: &[u8],
) -> Result<usize, EncodeError> {
    if bytes.is_empty() {
        return Err(EncodeError::InvalidLength);
    }
    let length = HEADER_LEN
        .checked_add(bytes.len())
        .ok_or(EncodeError::ValueTooLong)?;
    if length > MAX_MESSAGE_LEN {
        return Err(EncodeError::ValueTooLong);
    }
    require_output(output, length)?;
    let payload_len = u32::try_from(bytes.len()).map_err(|_| EncodeError::ValueTooLong)?;
    write_header(output, opcode, request_id, payload_len);
    output[HEADER_LEN..length].copy_from_slice(bytes);
    Ok(length)
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

fn decode_header(input: &[u8]) -> Result<Header, DecodeError> {
    if input.len() < HEADER_LEN || input.len() > MAX_MESSAGE_LEN {
        return Err(DecodeError::InvalidLength);
    }
    let magic = read_u32(input, 0);
    if magic != MAGIC {
        return Err(DecodeError::InvalidMagic(magic));
    }
    let version = u16::from_le_bytes([input[4], input[5]]);
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let opcode_raw = u16::from_le_bytes([input[6], input[7]]);
    let opcode = match opcode_raw {
        0x0001 => Opcode::SnapshotBegin,
        0x0002 => Opcode::SnapshotChunk,
        0x0010 => Opcode::AddUser,
        0x0011 => Opcode::RemoveUser,
        0x8000 => Opcode::Status,
        0x8001 => Opcode::SnapshotInfo,
        0x8002 => Opcode::SnapshotData,
        _ => return Err(DecodeError::UnknownOpcode(opcode_raw)),
    };
    let payload_len = read_u32(input, 16) as usize;
    if read_u32(input, 20) != 0 {
        return Err(DecodeError::NonZeroFlags(read_u32(input, 20)));
    }
    if payload_len.checked_add(HEADER_LEN) != Some(input.len()) {
        return Err(DecodeError::InvalidLength);
    }
    Ok(Header {
        opcode,
        request_id: read_u64(input, 8),
        payload_len,
    })
}

fn write_header(output: &mut [u8], opcode: Opcode, request_id: u64, payload_len: u32) {
    write_u32(output, 0, MAGIC);
    output[4..6].copy_from_slice(&VERSION.to_le_bytes());
    output[6..8].copy_from_slice(&opcode.wire_value().to_le_bytes());
    write_u64(output, 8, request_id);
    write_u32(output, 16, payload_len);
    write_u32(output, 20, 0);
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

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap_or([0; 4]))
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap_or([0; 8]))
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_round_trip_and_golden_header() {
        let request = SnapshotRequest {
            request_id: 0x8877_6655_4433_2211,
        };
        let mut bytes = [0u8; SNAPSHOT_REQUEST_LEN];
        request.encode(&mut bytes).unwrap();
        assert_eq!(&bytes[0..4], b"MUSR");
        assert_eq!(&bytes[4..8], &[1, 0, 1, 0]);
        assert_eq!(SnapshotRequest::decode(&bytes), Ok(request));
    }

    #[test]
    fn chunk_round_trip_and_limits() {
        let chunk = SnapshotChunk {
            request_id: 9,
            offset: 12,
            generation: 3,
            bytes: b"users",
        };
        let mut bytes = [0u8; 64];
        let len = chunk.encode(&mut bytes).unwrap();
        assert_eq!(SnapshotChunk::decode(&bytes[..len]), Ok(chunk));
        let oversized = SnapshotChunkRequest {
            request_id: 1,
            offset: 0,
            length: MAX_CHUNK_LEN as u32 + 1,
        };
        assert_eq!(
            oversized.encode(&mut bytes),
            Err(EncodeError::InvalidLength)
        );
    }

    #[test]
    fn mutations_and_status_round_trip() {
        let add = AddUser {
            request_id: 3,
            encoded_record: b"record",
        };
        let mut bytes = [0u8; 128];
        let len = add.encode(&mut bytes).unwrap();
        assert_eq!(AddUser::decode(&bytes[..len]), Ok(add));
        let remove = RemoveUser {
            request_id: 4,
            name: "alice",
        };
        let len = remove.encode(&mut bytes).unwrap();
        assert_eq!(RemoveUser::decode(&bytes[..len]), Ok(remove));
        let status = Status {
            request_id: 4,
            status: -13,
            generation: u64::MAX,
        };
        let len = status.encode(&mut bytes).unwrap();
        assert_eq!(Status::decode(&bytes[..len]), Ok(status));
    }

    #[test]
    fn malformed_headers_are_rejected() {
        let request = SnapshotRequest { request_id: 1 };
        let mut bytes = [0u8; SNAPSHOT_REQUEST_LEN];
        request.encode(&mut bytes).unwrap();
        bytes[0] = 0;
        assert!(matches!(
            SnapshotRequest::decode(&bytes),
            Err(DecodeError::InvalidMagic(_))
        ));
        request.encode(&mut bytes).unwrap();
        bytes[4] = 2;
        assert!(matches!(
            SnapshotRequest::decode(&bytes),
            Err(DecodeError::UnsupportedVersion(2))
        ));
        request.encode(&mut bytes).unwrap();
        bytes[6..8].copy_from_slice(&0x7777u16.to_le_bytes());
        assert!(matches!(
            decode_opcode(&bytes),
            Err(DecodeError::UnknownOpcode(0x7777))
        ));
    }

    #[test]
    fn short_extra_and_small_output_are_rejected() {
        assert_eq!(
            SnapshotRequest::decode(&[0; HEADER_LEN - 1]),
            Err(DecodeError::InvalidLength)
        );
        let request = SnapshotRequest { request_id: 1 };
        let mut bytes = [0u8; HEADER_LEN + 1];
        request.encode(&mut bytes).unwrap();
        assert_eq!(
            SnapshotRequest::decode(&bytes),
            Err(DecodeError::InvalidLength)
        );
        assert!(matches!(
            request.encode(&mut [0; HEADER_LEN - 1]),
            Err(EncodeError::BufferTooSmall { .. })
        ));
    }
}
