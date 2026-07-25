use crate::codec::{
    read_u8, read_u32, read_u64, require_decode, require_encode, write_u8, write_u32, write_u64,
};
use crate::{
    DecodeError, EncodeError, MemoryEntry, PixelFormat, Rect, TYPE_GET_DISPLAY_INFO,
    TYPE_RESOURCE_ATTACH_BACKING, TYPE_RESOURCE_CREATE_2D, TYPE_RESOURCE_DETACH_BACKING,
    TYPE_RESOURCE_FLUSH, TYPE_RESOURCE_UNREF, TYPE_SET_SCANOUT, TYPE_TRANSFER_TO_HOST_2D,
};

pub const COMMAND_HEADER_LEN: usize = 24;
const RESOURCE_OPERATION_LEN: usize = 32;
const RESOURCE_CREATE_2D_LEN: usize = 40;
const SET_SCANOUT_LEN: usize = 48;
const RESOURCE_FLUSH_LEN: usize = 48;
const TRANSFER_TO_HOST_2D_LEN: usize = 56;
const ATTACH_BACKING_PREFIX_LEN: usize = 32;
const MAX_BACKING_ENTRIES: usize = 4096;
const MAX_SCANOUT_ID: u32 = 15;

fn encode_header(buffer: &mut [u8], command_type: u32) {
    write_u32(buffer, 0, command_type);
    write_u32(buffer, 4, 0);
    write_u64(buffer, 8, 0);
    write_u32(buffer, 16, 0);
    write_u8(buffer, 20, 0);
    buffer[21..24].fill(0);
}

fn decode_header(buffer: &[u8]) -> Result<u32, DecodeError> {
    let command_type = read_u32(buffer, 0)?;
    let flags = read_u32(buffer, 4)?;
    let fence_id = read_u64(buffer, 8)?;
    let context_id = read_u32(buffer, 16)?;
    let ring_index = read_u8(buffer, 20)?;
    let padding = u32::from(read_u8(buffer, 21)?)
        | (u32::from(read_u8(buffer, 22)?) << 8)
        | (u32::from(read_u8(buffer, 23)?) << 16);
    for (offset, value) in [
        (4, u64::from(flags)),
        (8, fence_id),
        (16, u64::from(context_id)),
        (20, u64::from(ring_index)),
        (21, u64::from(padding)),
    ] {
        if value != 0 {
            return Err(DecodeError::NonZeroReserved {
                offset,
                actual: value,
            });
        }
    }
    Ok(command_type)
}

fn validate_resource_id(resource_id: u32) -> Result<(), EncodeError> {
    if resource_id == 0 {
        Err(EncodeError::InvalidValue)
    } else {
        Ok(())
    }
}

fn decode_resource_id(buffer: &[u8], offset: usize) -> Result<u32, DecodeError> {
    let resource_id = read_u32(buffer, offset)?;
    if resource_id == 0 {
        return Err(DecodeError::InvalidValue { offset, actual: 0 });
    }
    Ok(resource_id)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceCreate2d {
    pub resource_id: u32,
    pub format: PixelFormat,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceOperation {
    pub resource_id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetScanout {
    pub rect: Rect,
    pub scanout_id: u32,
    pub resource_id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferToHost2d {
    pub rect: Rect,
    pub offset: u64,
    pub resource_id: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct AttachBacking<'a> {
    pub resource_id: u32,
    pub entries: &'a [MemoryEntry],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachBackingView<'a> {
    resource_id: u32,
    count: usize,
    bytes: &'a [u8],
}

impl<'a> AttachBackingView<'a> {
    pub const fn resource_id(self) -> u32 {
        self.resource_id
    }

    pub const fn entry_count(self) -> usize {
        self.count
    }

    pub fn entry(self, index: usize) -> Result<Option<MemoryEntry>, DecodeError> {
        if index >= self.count {
            return Ok(None);
        }
        let offset = index
            .checked_mul(MemoryEntry::ENCODED_LEN)
            .ok_or(DecodeError::LengthOverflow)?;
        MemoryEntry::decode_at(self.bytes, offset).map(Some)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Command<'a> {
    GetDisplayInfo,
    ResourceCreate2d(ResourceCreate2d),
    ResourceUnref(ResourceOperation),
    SetScanout(SetScanout),
    ResourceFlush { rect: Rect, resource_id: u32 },
    TransferToHost2d(TransferToHost2d),
    ResourceAttachBacking(AttachBacking<'a>),
    ResourceDetachBacking(ResourceOperation),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodedCommand<'a> {
    GetDisplayInfo,
    ResourceCreate2d(ResourceCreate2d),
    ResourceUnref(ResourceOperation),
    SetScanout(SetScanout),
    ResourceFlush { rect: Rect, resource_id: u32 },
    TransferToHost2d(TransferToHost2d),
    ResourceAttachBacking(AttachBackingView<'a>),
    ResourceDetachBacking(ResourceOperation),
}

impl Command<'_> {
    pub fn encoded_len(self) -> Result<usize, EncodeError> {
        match self {
            Self::GetDisplayInfo => Ok(COMMAND_HEADER_LEN),
            Self::ResourceCreate2d(_) => Ok(RESOURCE_CREATE_2D_LEN),
            Self::ResourceUnref(_) | Self::ResourceDetachBacking(_) => Ok(RESOURCE_OPERATION_LEN),
            Self::SetScanout(_) | Self::ResourceFlush { .. } => Ok(SET_SCANOUT_LEN),
            Self::TransferToHost2d(_) => Ok(TRANSFER_TO_HOST_2D_LEN),
            Self::ResourceAttachBacking(command) => {
                if command.entries.is_empty() || command.entries.len() > MAX_BACKING_ENTRIES {
                    return Err(EncodeError::InvalidValue);
                }
                command
                    .entries
                    .len()
                    .checked_mul(MemoryEntry::ENCODED_LEN)
                    .and_then(|length| length.checked_add(ATTACH_BACKING_PREFIX_LEN))
                    .ok_or(EncodeError::LengthOverflow)
            }
        }
    }

    pub fn encode(self, buffer: &mut [u8]) -> Result<usize, EncodeError> {
        let length = self.encoded_len()?;
        require_encode(buffer, length)?;
        let buffer = &mut buffer[..length];
        buffer.fill(0);
        match self {
            Self::GetDisplayInfo => encode_header(buffer, TYPE_GET_DISPLAY_INFO),
            Self::ResourceCreate2d(command) => {
                validate_resource_id(command.resource_id)?;
                if command.width == 0 || command.height == 0 {
                    return Err(EncodeError::InvalidValue);
                }
                encode_header(buffer, TYPE_RESOURCE_CREATE_2D);
                write_u32(buffer, 24, command.resource_id);
                write_u32(buffer, 28, command.format.wire_value());
                write_u32(buffer, 32, command.width);
                write_u32(buffer, 36, command.height);
            }
            Self::ResourceUnref(command) => {
                encode_resource_operation(buffer, TYPE_RESOURCE_UNREF, command)?;
            }
            Self::SetScanout(command) => {
                if command.resource_id == 0 {
                    if command.rect != Rect::default() {
                        return Err(EncodeError::InvalidValue);
                    }
                } else {
                    command.rect.validate_nonempty()?;
                }
                if command.scanout_id > MAX_SCANOUT_ID {
                    return Err(EncodeError::InvalidValue);
                }
                encode_header(buffer, TYPE_SET_SCANOUT);
                command.rect.encode_at(buffer, 24);
                write_u32(buffer, 40, command.scanout_id);
                write_u32(buffer, 44, command.resource_id);
            }
            Self::ResourceFlush { rect, resource_id } => {
                validate_resource_id(resource_id)?;
                rect.validate_nonempty()?;
                encode_header(buffer, TYPE_RESOURCE_FLUSH);
                rect.encode_at(buffer, 24);
                write_u32(buffer, 40, resource_id);
                write_u32(buffer, 44, 0);
            }
            Self::TransferToHost2d(command) => {
                validate_resource_id(command.resource_id)?;
                command.rect.validate_nonempty()?;
                encode_header(buffer, TYPE_TRANSFER_TO_HOST_2D);
                command.rect.encode_at(buffer, 24);
                write_u64(buffer, 40, command.offset);
                write_u32(buffer, 48, command.resource_id);
                write_u32(buffer, 52, 0);
            }
            Self::ResourceAttachBacking(command) => {
                validate_resource_id(command.resource_id)?;
                encode_header(buffer, TYPE_RESOURCE_ATTACH_BACKING);
                write_u32(buffer, 24, command.resource_id);
                write_u32(
                    buffer,
                    28,
                    u32::try_from(command.entries.len())
                        .map_err(|_| EncodeError::LengthOverflow)?,
                );
                for (index, entry) in command.entries.iter().enumerate() {
                    let offset = ATTACH_BACKING_PREFIX_LEN + index * MemoryEntry::ENCODED_LEN;
                    entry.encode_at(buffer, offset)?;
                }
            }
            Self::ResourceDetachBacking(command) => {
                encode_resource_operation(buffer, TYPE_RESOURCE_DETACH_BACKING, command)?;
            }
        }
        Ok(length)
    }
}

fn encode_resource_operation(
    buffer: &mut [u8],
    command_type: u32,
    command: ResourceOperation,
) -> Result<(), EncodeError> {
    validate_resource_id(command.resource_id)?;
    encode_header(buffer, command_type);
    write_u32(buffer, 24, command.resource_id);
    write_u32(buffer, 28, 0);
    Ok(())
}

impl<'a> DecodedCommand<'a> {
    pub fn decode(buffer: &'a [u8]) -> Result<Self, DecodeError> {
        if buffer.len() < COMMAND_HEADER_LEN {
            return Err(DecodeError::InvalidLength {
                expected: COMMAND_HEADER_LEN,
                actual: buffer.len(),
            });
        }
        let command_type = decode_header(buffer)?;
        match command_type {
            TYPE_GET_DISPLAY_INFO => {
                require_decode(buffer, COMMAND_HEADER_LEN)?;
                Ok(Self::GetDisplayInfo)
            }
            TYPE_RESOURCE_CREATE_2D => {
                require_decode(buffer, RESOURCE_CREATE_2D_LEN)?;
                let format_value = read_u32(buffer, 28)?;
                let format =
                    PixelFormat::from_wire(format_value).ok_or(DecodeError::InvalidValue {
                        offset: 28,
                        actual: u64::from(format_value),
                    })?;
                let width = read_u32(buffer, 32)?;
                let height = read_u32(buffer, 36)?;
                if width == 0 || height == 0 {
                    return Err(DecodeError::InvalidValue {
                        offset: 32,
                        actual: u64::from(width) << 32 | u64::from(height),
                    });
                }
                Ok(Self::ResourceCreate2d(ResourceCreate2d {
                    resource_id: decode_resource_id(buffer, 24)?,
                    format,
                    width,
                    height,
                }))
            }
            TYPE_RESOURCE_UNREF => decode_resource_operation(buffer, Self::ResourceUnref),
            TYPE_SET_SCANOUT => {
                require_decode(buffer, SET_SCANOUT_LEN)?;
                let scanout_id = read_u32(buffer, 40)?;
                if scanout_id > MAX_SCANOUT_ID {
                    return Err(DecodeError::InvalidValue {
                        offset: 40,
                        actual: u64::from(scanout_id),
                    });
                }
                let resource_id = read_u32(buffer, 44)?;
                let rect = Rect::decode_at(buffer, 24)?;
                if resource_id == 0 {
                    if rect != Rect::default() {
                        return Err(DecodeError::InvalidValue {
                            offset: 24,
                            actual: 0,
                        });
                    }
                } else if !rect.is_nonempty()
                    || rect.x.checked_add(rect.width).is_none()
                    || rect.y.checked_add(rect.height).is_none()
                {
                    return Err(DecodeError::InvalidValue {
                        offset: 24,
                        actual: 0,
                    });
                }
                Ok(Self::SetScanout(SetScanout {
                    rect,
                    scanout_id,
                    resource_id,
                }))
            }
            TYPE_RESOURCE_FLUSH => {
                require_decode(buffer, RESOURCE_FLUSH_LEN)?;
                decode_reserved_u32(buffer, 44)?;
                Ok(Self::ResourceFlush {
                    rect: Rect::decode_nonempty_at(buffer, 24)?,
                    resource_id: decode_resource_id(buffer, 40)?,
                })
            }
            TYPE_TRANSFER_TO_HOST_2D => {
                require_decode(buffer, TRANSFER_TO_HOST_2D_LEN)?;
                decode_reserved_u32(buffer, 52)?;
                Ok(Self::TransferToHost2d(TransferToHost2d {
                    rect: Rect::decode_nonempty_at(buffer, 24)?,
                    offset: read_u64(buffer, 40)?,
                    resource_id: decode_resource_id(buffer, 48)?,
                }))
            }
            TYPE_RESOURCE_ATTACH_BACKING => {
                if buffer.len() < ATTACH_BACKING_PREFIX_LEN {
                    return Err(DecodeError::InvalidLength {
                        expected: ATTACH_BACKING_PREFIX_LEN,
                        actual: buffer.len(),
                    });
                }
                let count = read_u32(buffer, 28)? as usize;
                if count == 0 || count > MAX_BACKING_ENTRIES {
                    return Err(DecodeError::InvalidValue {
                        offset: 28,
                        actual: count as u64,
                    });
                }
                let expected = count
                    .checked_mul(MemoryEntry::ENCODED_LEN)
                    .and_then(|length| length.checked_add(ATTACH_BACKING_PREFIX_LEN))
                    .ok_or(DecodeError::LengthOverflow)?;
                require_decode(buffer, expected)?;
                let entries = &buffer[ATTACH_BACKING_PREFIX_LEN..];
                for index in 0..count {
                    let offset = index * MemoryEntry::ENCODED_LEN;
                    let _ = MemoryEntry::decode_at(entries, offset)?;
                }
                Ok(Self::ResourceAttachBacking(AttachBackingView {
                    resource_id: decode_resource_id(buffer, 24)?,
                    count,
                    bytes: entries,
                }))
            }
            TYPE_RESOURCE_DETACH_BACKING => {
                decode_resource_operation(buffer, Self::ResourceDetachBacking)
            }
            _ => Err(DecodeError::UnknownCommand {
                actual: command_type,
            }),
        }
    }
}

fn decode_resource_operation<'a>(
    buffer: &'a [u8],
    wrap: impl FnOnce(ResourceOperation) -> DecodedCommand<'a>,
) -> Result<DecodedCommand<'a>, DecodeError> {
    require_decode(buffer, RESOURCE_OPERATION_LEN)?;
    decode_reserved_u32(buffer, 28)?;
    Ok(wrap(ResourceOperation {
        resource_id: decode_resource_id(buffer, 24)?,
    }))
}

fn decode_reserved_u32(buffer: &[u8], offset: usize) -> Result<(), DecodeError> {
    let reserved = read_u32(buffer, offset)?;
    if reserved != 0 {
        return Err(DecodeError::NonZeroReserved {
            offset,
            actual: u64::from(reserved),
        });
    }
    Ok(())
}
