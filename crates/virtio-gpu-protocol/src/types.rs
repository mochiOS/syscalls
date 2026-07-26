use core::fmt;

use crate::codec::{read_u32, read_u64, write_u32, write_u64};

pub const VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM: u32 = 1;
pub const VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    BufferTooSmall { required: usize, actual: usize },
    InvalidValue,
    LengthOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    InvalidLength { expected: usize, actual: usize },
    UnknownCommand { actual: u32 },
    UnknownResponse { actual: u32 },
    UnexpectedResponse { expected: u32, actual: u32 },
    NonZeroReserved { offset: usize, actual: u64 },
    InvalidValue { offset: usize, actual: u64 },
    LengthOverflow,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooSmall { required, actual } => {
                write!(f, "buffer too small: required {required}, actual {actual}")
            }
            Self::InvalidValue => f.write_str("message contains an invalid value"),
            Self::LengthOverflow => f.write_str("message length overflow"),
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "invalid length: expected {expected}, actual {actual}")
            }
            Self::UnknownCommand { actual } => write!(f, "unknown command: {actual:#010x}"),
            Self::UnknownResponse { actual } => write!(f, "unknown response: {actual:#010x}"),
            Self::UnexpectedResponse { expected, actual } => write!(
                f,
                "unexpected response: expected {expected:#010x}, actual {actual:#010x}"
            ),
            Self::NonZeroReserved { offset, actual } => {
                write!(f, "reserved field at {offset} is non-zero: {actual:#x}")
            }
            Self::InvalidValue { offset, actual } => {
                write!(f, "invalid value at {offset}: {actual:#x}")
            }
            Self::LengthOverflow => f.write_str("message length overflow"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PixelFormat(u32);

impl PixelFormat {
    pub const B8G8R8A8_UNORM: Self = Self(VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM);
    pub const B8G8R8X8_UNORM: Self = Self(VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM);

    pub const fn wire_value(self) -> u32 {
        self.0
    }

    pub const fn from_wire(value: u32) -> Option<Self> {
        if matches!(
            value,
            VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM | VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM
        ) {
            Some(Self(value))
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Box3d {
    pub x: u32,
    pub y: u32,
    pub z: u32,
    pub width: u32,
    pub height: u32,
    pub depth: u32,
}

impl Box3d {
    pub const ENCODED_LEN: usize = 24;

    pub const fn is_nonempty(self) -> bool {
        self.width != 0 && self.height != 0 && self.depth != 0
    }

    pub fn validate_nonempty(self) -> Result<(), EncodeError> {
        if !self.is_nonempty()
            || self.x.checked_add(self.width).is_none()
            || self.y.checked_add(self.height).is_none()
            || self.z.checked_add(self.depth).is_none()
        {
            return Err(EncodeError::InvalidValue);
        }
        Ok(())
    }

    pub(crate) fn encode_at(self, buffer: &mut [u8], offset: usize) {
        write_u32(buffer, offset, self.x);
        write_u32(buffer, offset + 4, self.y);
        write_u32(buffer, offset + 8, self.z);
        write_u32(buffer, offset + 12, self.width);
        write_u32(buffer, offset + 16, self.height);
        write_u32(buffer, offset + 20, self.depth);
    }

    pub(crate) fn decode_nonempty_at(buffer: &[u8], offset: usize) -> Result<Self, DecodeError> {
        let value = Self {
            x: read_u32(buffer, offset)?,
            y: read_u32(buffer, offset + 4)?,
            z: read_u32(buffer, offset + 8)?,
            width: read_u32(buffer, offset + 12)?,
            height: read_u32(buffer, offset + 16)?,
            depth: read_u32(buffer, offset + 20)?,
        };
        if !value.is_nonempty()
            || value.x.checked_add(value.width).is_none()
            || value.y.checked_add(value.height).is_none()
            || value.z.checked_add(value.depth).is_none()
        {
            return Err(DecodeError::InvalidValue {
                offset,
                actual: u64::from(value.width) << 32 | u64::from(value.height),
            });
        }
        Ok(value)
    }
}

impl Rect {
    pub const ENCODED_LEN: usize = 16;

    pub const fn is_nonempty(self) -> bool {
        self.width != 0 && self.height != 0
    }

    pub fn validate_nonempty(self) -> Result<(), EncodeError> {
        if !self.is_nonempty()
            || self.x.checked_add(self.width).is_none()
            || self.y.checked_add(self.height).is_none()
        {
            return Err(EncodeError::InvalidValue);
        }
        Ok(())
    }

    pub(crate) fn encode_at(self, buffer: &mut [u8], offset: usize) {
        write_u32(buffer, offset, self.x);
        write_u32(buffer, offset + 4, self.y);
        write_u32(buffer, offset + 8, self.width);
        write_u32(buffer, offset + 12, self.height);
    }

    pub(crate) fn decode_at(buffer: &[u8], offset: usize) -> Result<Self, DecodeError> {
        Ok(Self {
            x: read_u32(buffer, offset)?,
            y: read_u32(buffer, offset + 4)?,
            width: read_u32(buffer, offset + 8)?,
            height: read_u32(buffer, offset + 12)?,
        })
    }

    pub(crate) fn decode_nonempty_at(buffer: &[u8], offset: usize) -> Result<Self, DecodeError> {
        let rect = Self::decode_at(buffer, offset)?;
        if !rect.is_nonempty()
            || rect.x.checked_add(rect.width).is_none()
            || rect.y.checked_add(rect.height).is_none()
        {
            return Err(DecodeError::InvalidValue {
                offset,
                actual: u64::from(rect.width) << 32 | u64::from(rect.height),
            });
        }
        Ok(rect)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryEntry {
    pub address: u64,
    pub length: u32,
}

impl MemoryEntry {
    pub const ENCODED_LEN: usize = 16;

    pub(crate) fn encode_at(self, buffer: &mut [u8], offset: usize) -> Result<(), EncodeError> {
        if self.length == 0 || self.address.checked_add(u64::from(self.length)).is_none() {
            return Err(EncodeError::InvalidValue);
        }
        write_u64(buffer, offset, self.address);
        write_u32(buffer, offset + 8, self.length);
        write_u32(buffer, offset + 12, 0);
        Ok(())
    }

    pub(crate) fn decode_at(buffer: &[u8], offset: usize) -> Result<Self, DecodeError> {
        let address = read_u64(buffer, offset)?;
        let length = read_u32(buffer, offset + 8)?;
        let reserved = read_u32(buffer, offset + 12)?;
        if reserved != 0 {
            return Err(DecodeError::NonZeroReserved {
                offset: offset + 12,
                actual: u64::from(reserved),
            });
        }
        if length == 0 || address.checked_add(u64::from(length)).is_none() {
            return Err(DecodeError::InvalidValue {
                offset,
                actual: address,
            });
        }
        Ok(Self { address, length })
    }
}
