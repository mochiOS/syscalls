use crate::codec::{
    read_u8, read_u32, read_u64, require_decode, require_encode, write_u8, write_u32, write_u64,
};
use crate::{
    Box3d, DecodeError, EncodeError, MemoryEntry, PixelFormat, Rect, TYPE_CTX_ATTACH_RESOURCE,
    TYPE_CTX_CREATE, TYPE_CTX_DESTROY, TYPE_CTX_DETACH_RESOURCE, TYPE_GET_CAPSET,
    TYPE_GET_CAPSET_INFO, TYPE_GET_DISPLAY_INFO, TYPE_MOVE_CURSOR, TYPE_RESOURCE_ATTACH_BACKING,
    TYPE_RESOURCE_CREATE_2D, TYPE_RESOURCE_CREATE_3D, TYPE_RESOURCE_DETACH_BACKING,
    TYPE_RESOURCE_FLUSH, TYPE_RESOURCE_UNREF, TYPE_SET_SCANOUT, TYPE_SUBMIT_3D,
    TYPE_TRANSFER_FROM_HOST_3D, TYPE_TRANSFER_TO_HOST_2D, TYPE_TRANSFER_TO_HOST_3D,
    TYPE_UPDATE_CURSOR,
};

pub const COMMAND_HEADER_LEN: usize = 24;
const RESOURCE_OPERATION_LEN: usize = 32;
const RESOURCE_CREATE_2D_LEN: usize = 40;
const SET_SCANOUT_LEN: usize = 48;
const RESOURCE_FLUSH_LEN: usize = 48;
const TRANSFER_TO_HOST_2D_LEN: usize = 56;
const ATTACH_BACKING_PREFIX_LEN: usize = 32;
const CONTEXT_CREATE_LEN: usize = 96;
const CONTEXT_RESOURCE_LEN: usize = 32;
const RESOURCE_CREATE_3D_LEN: usize = 72;
const TRANSFER_HOST_3D_LEN: usize = 72;
const SUBMIT_3D_PREFIX_LEN: usize = 32;
const CONTEXT_DEBUG_NAME_LEN: usize = 64;
const MAX_SUBMIT_3D_SIZE: usize = 16 * 1024 * 1024;
const MAX_BACKING_ENTRIES: usize = 4096;
const MAX_SCANOUT_ID: u32 = 15;
const CURSOR_COMMAND_LEN: usize = 56;

fn encode_header(buffer: &mut [u8], command_type: u32) {
    encode_context_header(buffer, command_type, 0);
}

fn encode_context_header(buffer: &mut [u8], command_type: u32, context_id: u32) {
    write_u32(buffer, 0, command_type);
    write_u32(buffer, 4, 0);
    write_u64(buffer, 8, 0);
    write_u32(buffer, 16, context_id);
    write_u8(buffer, 20, 0);
    buffer[21..24].fill(0);
}

fn decode_header(buffer: &[u8]) -> Result<(u32, u32), DecodeError> {
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
    Ok((command_type, context_id))
}

fn require_context(context_id: u32) -> Result<u32, DecodeError> {
    if context_id == 0 {
        Err(DecodeError::InvalidValue {
            offset: 16,
            actual: 0,
        })
    } else {
        Ok(context_id)
    }
}

fn require_no_context(context_id: u32) -> Result<(), DecodeError> {
    if context_id == 0 {
        Ok(())
    } else {
        Err(DecodeError::NonZeroReserved {
            offset: 16,
            actual: u64::from(context_id),
        })
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorPosition {
    pub scanout_id: u32,
    pub x: u32,
    pub y: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorUpdate {
    pub position: CursorPosition,
    pub resource_id: u32,
    pub hotspot_x: u32,
    pub hotspot_y: u32,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetCapset {
    pub capset_id: u32,
    pub version: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct ContextCreate<'a> {
    pub context_id: u32,
    pub context_init: u32,
    pub debug_name: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextCreateView<'a> {
    pub context_id: u32,
    pub context_init: u32,
    pub debug_name: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextResource {
    pub context_id: u32,
    pub resource_id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceCreate3d {
    pub resource_id: u32,
    pub target: u32,
    pub format: u32,
    pub bind: u32,
    pub width: u32,
    pub height: u32,
    pub depth: u32,
    pub array_size: u32,
    pub last_level: u32,
    pub samples: u32,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferHost3d {
    pub context_id: u32,
    pub box_3d: Box3d,
    pub offset: u64,
    pub resource_id: u32,
    pub level: u32,
    pub stride: u32,
    pub layer_stride: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Submit3d<'a> {
    pub context_id: u32,
    pub commands: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Submit3dView<'a> {
    pub context_id: u32,
    pub commands: &'a [u8],
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
    GetCapsetInfo { index: u32 },
    GetCapset(GetCapset),
    ContextCreate(ContextCreate<'a>),
    ContextDestroy { context_id: u32 },
    ContextAttachResource(ContextResource),
    ContextDetachResource(ContextResource),
    ResourceCreate3d(ResourceCreate3d),
    TransferToHost3d(TransferHost3d),
    TransferFromHost3d(TransferHost3d),
    Submit3d(Submit3d<'a>),
    UpdateCursor(CursorUpdate),
    MoveCursor(CursorPosition),
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
    GetCapsetInfo { index: u32 },
    GetCapset(GetCapset),
    ContextCreate(ContextCreateView<'a>),
    ContextDestroy { context_id: u32 },
    ContextAttachResource(ContextResource),
    ContextDetachResource(ContextResource),
    ResourceCreate3d(ResourceCreate3d),
    TransferToHost3d(TransferHost3d),
    TransferFromHost3d(TransferHost3d),
    Submit3d(Submit3dView<'a>),
    UpdateCursor(CursorUpdate),
    MoveCursor(CursorPosition),
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
            Self::GetCapsetInfo { .. }
            | Self::GetCapset(_)
            | Self::ContextAttachResource(_)
            | Self::ContextDetachResource(_) => Ok(CONTEXT_RESOURCE_LEN),
            Self::ContextCreate(command) => {
                if command.context_id == 0 || command.debug_name.len() > CONTEXT_DEBUG_NAME_LEN {
                    return Err(EncodeError::InvalidValue);
                }
                Ok(CONTEXT_CREATE_LEN)
            }
            Self::ContextDestroy { context_id } => {
                if context_id == 0 {
                    return Err(EncodeError::InvalidValue);
                }
                Ok(COMMAND_HEADER_LEN)
            }
            Self::ResourceCreate3d(_) => Ok(RESOURCE_CREATE_3D_LEN),
            Self::TransferToHost3d(_) | Self::TransferFromHost3d(_) => Ok(TRANSFER_HOST_3D_LEN),
            Self::Submit3d(command) => {
                if command.context_id == 0
                    || command.commands.is_empty()
                    || command.commands.len() > MAX_SUBMIT_3D_SIZE
                    || command.commands.len() % 4 != 0
                {
                    return Err(EncodeError::InvalidValue);
                }
                command
                    .commands
                    .len()
                    .checked_add(SUBMIT_3D_PREFIX_LEN)
                    .ok_or(EncodeError::LengthOverflow)
            }
            Self::UpdateCursor(_) | Self::MoveCursor(_) => Ok(CURSOR_COMMAND_LEN),
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
            Self::GetCapsetInfo { index } => {
                encode_header(buffer, TYPE_GET_CAPSET_INFO);
                write_u32(buffer, 24, index);
                write_u32(buffer, 28, 0);
            }
            Self::GetCapset(command) => {
                if command.capset_id == 0 {
                    return Err(EncodeError::InvalidValue);
                }
                encode_header(buffer, TYPE_GET_CAPSET);
                write_u32(buffer, 24, command.capset_id);
                write_u32(buffer, 28, command.version);
            }
            Self::ContextCreate(command) => {
                encode_context_header(buffer, TYPE_CTX_CREATE, command.context_id);
                write_u32(
                    buffer,
                    24,
                    u32::try_from(command.debug_name.len())
                        .map_err(|_| EncodeError::LengthOverflow)?,
                );
                write_u32(buffer, 28, command.context_init);
                buffer[32..32 + command.debug_name.len()].copy_from_slice(command.debug_name);
            }
            Self::ContextDestroy { context_id } => {
                encode_context_header(buffer, TYPE_CTX_DESTROY, context_id);
            }
            Self::ContextAttachResource(command) => {
                encode_context_resource(buffer, TYPE_CTX_ATTACH_RESOURCE, command)?;
            }
            Self::ContextDetachResource(command) => {
                encode_context_resource(buffer, TYPE_CTX_DETACH_RESOURCE, command)?;
            }
            Self::ResourceCreate3d(command) => {
                validate_resource_id(command.resource_id)?;
                if command.width == 0
                    || command.height == 0
                    || command.depth == 0
                    || command.array_size == 0
                {
                    return Err(EncodeError::InvalidValue);
                }
                encode_header(buffer, TYPE_RESOURCE_CREATE_3D);
                for (offset, value) in [
                    (24, command.resource_id),
                    (28, command.target),
                    (32, command.format),
                    (36, command.bind),
                    (40, command.width),
                    (44, command.height),
                    (48, command.depth),
                    (52, command.array_size),
                    (56, command.last_level),
                    (60, command.samples),
                    (64, command.flags),
                    (68, 0),
                ] {
                    write_u32(buffer, offset, value);
                }
            }
            Self::TransferToHost3d(command) => {
                encode_transfer_host_3d(buffer, TYPE_TRANSFER_TO_HOST_3D, command)?;
            }
            Self::TransferFromHost3d(command) => {
                encode_transfer_host_3d(buffer, TYPE_TRANSFER_FROM_HOST_3D, command)?;
            }
            Self::Submit3d(command) => {
                encode_context_header(buffer, TYPE_SUBMIT_3D, command.context_id);
                write_u32(
                    buffer,
                    24,
                    u32::try_from(command.commands.len())
                        .map_err(|_| EncodeError::LengthOverflow)?,
                );
                write_u32(buffer, 28, 0);
                buffer[SUBMIT_3D_PREFIX_LEN..].copy_from_slice(command.commands);
            }
            Self::UpdateCursor(command) => {
                encode_cursor_position(buffer, TYPE_UPDATE_CURSOR, command.position)?;
                write_u32(buffer, 40, command.resource_id);
                write_u32(buffer, 44, command.hotspot_x);
                write_u32(buffer, 48, command.hotspot_y);
                write_u32(buffer, 52, 0);
            }
            Self::MoveCursor(position) => {
                encode_cursor_position(buffer, TYPE_MOVE_CURSOR, position)?;
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

fn encode_context_resource(
    buffer: &mut [u8],
    command_type: u32,
    command: ContextResource,
) -> Result<(), EncodeError> {
    if command.context_id == 0 {
        return Err(EncodeError::InvalidValue);
    }
    validate_resource_id(command.resource_id)?;
    encode_context_header(buffer, command_type, command.context_id);
    write_u32(buffer, 24, command.resource_id);
    write_u32(buffer, 28, 0);
    Ok(())
}

fn encode_transfer_host_3d(
    buffer: &mut [u8],
    command_type: u32,
    command: TransferHost3d,
) -> Result<(), EncodeError> {
    if command.context_id == 0 {
        return Err(EncodeError::InvalidValue);
    }
    validate_resource_id(command.resource_id)?;
    command.box_3d.validate_nonempty()?;
    encode_context_header(buffer, command_type, command.context_id);
    command.box_3d.encode_at(buffer, 24);
    write_u64(buffer, 48, command.offset);
    write_u32(buffer, 56, command.resource_id);
    write_u32(buffer, 60, command.level);
    write_u32(buffer, 64, command.stride);
    write_u32(buffer, 68, command.layer_stride);
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
        let (command_type, context_id) = decode_header(buffer)?;
        if !matches!(
            command_type,
            TYPE_CTX_CREATE
                | TYPE_CTX_DESTROY
                | TYPE_CTX_ATTACH_RESOURCE
                | TYPE_CTX_DETACH_RESOURCE
                | TYPE_TRANSFER_TO_HOST_3D
                | TYPE_TRANSFER_FROM_HOST_3D
                | TYPE_SUBMIT_3D
        ) {
            require_no_context(context_id)?;
        }
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
                    resource_id: read_u32(buffer, 40)?,
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
            TYPE_GET_CAPSET_INFO => {
                require_decode(buffer, CONTEXT_RESOURCE_LEN)?;
                decode_reserved_u32(buffer, 28)?;
                Ok(Self::GetCapsetInfo {
                    index: read_u32(buffer, 24)?,
                })
            }
            TYPE_GET_CAPSET => {
                require_decode(buffer, CONTEXT_RESOURCE_LEN)?;
                let capset_id = read_u32(buffer, 24)?;
                if capset_id == 0 {
                    return Err(DecodeError::InvalidValue {
                        offset: 24,
                        actual: 0,
                    });
                }
                Ok(Self::GetCapset(GetCapset {
                    capset_id,
                    version: read_u32(buffer, 28)?,
                }))
            }
            TYPE_CTX_CREATE => {
                require_decode(buffer, CONTEXT_CREATE_LEN)?;
                let context_id = require_context(context_id)?;
                let name_len = read_u32(buffer, 24)? as usize;
                if name_len > CONTEXT_DEBUG_NAME_LEN {
                    return Err(DecodeError::InvalidValue {
                        offset: 24,
                        actual: name_len as u64,
                    });
                }
                if buffer[32 + name_len..CONTEXT_CREATE_LEN]
                    .iter()
                    .any(|byte| *byte != 0)
                {
                    return Err(DecodeError::NonZeroReserved {
                        offset: 32 + name_len,
                        actual: 1,
                    });
                }
                Ok(Self::ContextCreate(ContextCreateView {
                    context_id,
                    context_init: read_u32(buffer, 28)?,
                    debug_name: &buffer[32..32 + name_len],
                }))
            }
            TYPE_CTX_DESTROY => {
                require_decode(buffer, COMMAND_HEADER_LEN)?;
                Ok(Self::ContextDestroy {
                    context_id: require_context(context_id)?,
                })
            }
            TYPE_CTX_ATTACH_RESOURCE => {
                decode_context_resource(buffer, context_id, Self::ContextAttachResource)
            }
            TYPE_CTX_DETACH_RESOURCE => {
                decode_context_resource(buffer, context_id, Self::ContextDetachResource)
            }
            TYPE_RESOURCE_CREATE_3D => {
                require_decode(buffer, RESOURCE_CREATE_3D_LEN)?;
                decode_reserved_u32(buffer, 68)?;
                let command = ResourceCreate3d {
                    resource_id: decode_resource_id(buffer, 24)?,
                    target: read_u32(buffer, 28)?,
                    format: read_u32(buffer, 32)?,
                    bind: read_u32(buffer, 36)?,
                    width: read_u32(buffer, 40)?,
                    height: read_u32(buffer, 44)?,
                    depth: read_u32(buffer, 48)?,
                    array_size: read_u32(buffer, 52)?,
                    last_level: read_u32(buffer, 56)?,
                    samples: read_u32(buffer, 60)?,
                    flags: read_u32(buffer, 64)?,
                };
                if command.width == 0
                    || command.height == 0
                    || command.depth == 0
                    || command.array_size == 0
                {
                    return Err(DecodeError::InvalidValue {
                        offset: 40,
                        actual: u64::from(command.width) << 32 | u64::from(command.height),
                    });
                }
                Ok(Self::ResourceCreate3d(command))
            }
            TYPE_TRANSFER_TO_HOST_3D => {
                decode_transfer_host_3d(buffer, context_id, Self::TransferToHost3d)
            }
            TYPE_TRANSFER_FROM_HOST_3D => {
                decode_transfer_host_3d(buffer, context_id, Self::TransferFromHost3d)
            }
            TYPE_SUBMIT_3D => {
                if buffer.len() < SUBMIT_3D_PREFIX_LEN {
                    return Err(DecodeError::InvalidLength {
                        expected: SUBMIT_3D_PREFIX_LEN,
                        actual: buffer.len(),
                    });
                }
                let context_id = require_context(context_id)?;
                let size = read_u32(buffer, 24)? as usize;
                decode_reserved_u32(buffer, 28)?;
                if size == 0 || size > MAX_SUBMIT_3D_SIZE || size % 4 != 0 {
                    return Err(DecodeError::InvalidValue {
                        offset: 24,
                        actual: size as u64,
                    });
                }
                let expected = size
                    .checked_add(SUBMIT_3D_PREFIX_LEN)
                    .ok_or(DecodeError::LengthOverflow)?;
                require_decode(buffer, expected)?;
                Ok(Self::Submit3d(Submit3dView {
                    context_id,
                    commands: &buffer[SUBMIT_3D_PREFIX_LEN..],
                }))
            }
            TYPE_UPDATE_CURSOR => {
                require_decode(buffer, CURSOR_COMMAND_LEN)?;
                decode_reserved_u32(buffer, 36)?;
                decode_reserved_u32(buffer, 52)?;
                Ok(Self::UpdateCursor(CursorUpdate {
                    position: decode_cursor_position(buffer)?,
                    resource_id: read_u32(buffer, 40)?,
                    hotspot_x: read_u32(buffer, 44)?,
                    hotspot_y: read_u32(buffer, 48)?,
                }))
            }
            TYPE_MOVE_CURSOR => {
                require_decode(buffer, CURSOR_COMMAND_LEN)?;
                for offset in [36, 40, 44, 48, 52] {
                    decode_reserved_u32(buffer, offset)?;
                }
                Ok(Self::MoveCursor(decode_cursor_position(buffer)?))
            }
            _ => Err(DecodeError::UnknownCommand {
                actual: command_type,
            }),
        }
    }
}

fn encode_cursor_position(
    buffer: &mut [u8],
    command_type: u32,
    position: CursorPosition,
) -> Result<(), EncodeError> {
    if position.scanout_id > MAX_SCANOUT_ID {
        return Err(EncodeError::InvalidValue);
    }
    encode_header(buffer, command_type);
    write_u32(buffer, 24, position.scanout_id);
    write_u32(buffer, 28, position.x);
    write_u32(buffer, 32, position.y);
    write_u32(buffer, 36, 0);
    Ok(())
}

fn decode_cursor_position(buffer: &[u8]) -> Result<CursorPosition, DecodeError> {
    let scanout_id = read_u32(buffer, 24)?;
    if scanout_id > MAX_SCANOUT_ID {
        return Err(DecodeError::InvalidValue {
            offset: 24,
            actual: u64::from(scanout_id),
        });
    }
    Ok(CursorPosition {
        scanout_id,
        x: read_u32(buffer, 28)?,
        y: read_u32(buffer, 32)?,
    })
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

fn decode_context_resource<'a>(
    buffer: &'a [u8],
    context_id: u32,
    wrap: impl FnOnce(ContextResource) -> DecodedCommand<'a>,
) -> Result<DecodedCommand<'a>, DecodeError> {
    require_decode(buffer, CONTEXT_RESOURCE_LEN)?;
    decode_reserved_u32(buffer, 28)?;
    Ok(wrap(ContextResource {
        context_id: require_context(context_id)?,
        resource_id: decode_resource_id(buffer, 24)?,
    }))
}

fn decode_transfer_host_3d<'a>(
    buffer: &'a [u8],
    context_id: u32,
    wrap: impl FnOnce(TransferHost3d) -> DecodedCommand<'a>,
) -> Result<DecodedCommand<'a>, DecodeError> {
    require_decode(buffer, TRANSFER_HOST_3D_LEN)?;
    Ok(wrap(TransferHost3d {
        context_id: require_context(context_id)?,
        box_3d: Box3d::decode_nonempty_at(buffer, 24)?,
        offset: read_u64(buffer, 48)?,
        resource_id: decode_resource_id(buffer, 56)?,
        level: read_u32(buffer, 60)?,
        stride: read_u32(buffer, 64)?,
        layer_stride: read_u32(buffer, 68)?,
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
