#![no_std]

pub const MAGIC: [u8; 4] = *b"MWSP";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 24;
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;
pub const MAX_CLIPBOARD_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CHUNK_BYTES: usize = MAX_MESSAGE_LEN - HEADER_LEN - 16;
pub const MAX_CONTENT_TYPE_LEN: usize = 127;
pub const MAX_EXTENSION_LEN: usize = 63;
pub const MAX_BUNDLE_ID_LEN: usize = 255;
pub const MAX_PATH_LEN: usize = 4095;
pub const MAX_HANDLER_NAME_LEN: usize = 255;
pub const MAX_ASSOCIATION_HANDLERS: usize = 256;
pub const MAX_CONTROL_CENTER_ITEM_ID_LEN: usize = 64;
pub const MAX_CONTROL_CENTER_CARD_TITLE_LEN: usize = 96;
pub const MAX_CONTROL_CENTER_CARD_BODY_LEN: usize = 2048;
pub const MAX_CONTROL_CENTER_CARDS: usize = 64;
pub const CONTROL_CENTER_CARD_PREFIX_LEN: usize = 8;
pub const MAX_NOTIFICATION_TITLE_LEN: usize = 128;
pub const MAX_NOTIFICATION_BODY_LEN: usize = 1024;
pub const MAX_NOTIFICATIONS: usize = 128;
pub const NOTIFICATION_PREFIX_LEN: usize = 24;
pub const MAX_NOTIFICATION_SETTINGS_LEN: usize = 16 * 1024;
pub const DOCUMENT_DELIVERY_MAGIC: [u8; 8] = *b"MAPPDOC1";
pub const DOCUMENT_DELIVERY_PREFIX_LEN: usize = 16;

pub const OP_CLIPBOARD_SET_BEGIN: u16 = 0x0100;
pub const OP_CLIPBOARD_SET_CHUNK: u16 = 0x0101;
pub const OP_CLIPBOARD_SET_COMMIT: u16 = 0x0102;
pub const OP_CLIPBOARD_SNAPSHOT: u16 = 0x0103;
pub const OP_CLIPBOARD_READ: u16 = 0x0104;
pub const OP_ASSOCIATION_SET: u16 = 0x0200;
pub const OP_ASSOCIATION_REMOVE: u16 = 0x0201;
pub const OP_ASSOCIATION_RESOLVE: u16 = 0x0202;
pub const OP_DOCUMENT_OPEN: u16 = 0x0203;
pub const OP_ASSOCIATION_HANDLERS: u16 = 0x0204;
pub const OP_FILE_PANEL: u16 = 0x0300;
pub const OP_FILE_PANEL_COMPLETE: u16 = 0x0301;
pub const OP_FILE_PANEL_FINISH: u16 = 0x0302;
pub const OP_FILE_PANEL_RETRY: u16 = 0x0303;
pub const OP_APPLICATION_REGISTER: u16 = 0x0400;
pub const OP_APPLICATION_ACTIVATE: u16 = 0x0401;
pub const OP_CONTROL_CENTER_CARD_REGISTER: u16 = 0x0500;
pub const OP_CONTROL_CENTER_CARD_SNAPSHOT: u16 = 0x0501;
pub const OP_NOTIFICATION_POST: u16 = 0x0600;
pub const OP_NOTIFICATION_SNAPSHOT: u16 = 0x0601;
pub const OP_NOTIFICATION_MARK_ALL_READ: u16 = 0x0602;
pub const OP_NOTIFICATION_REMOVE: u16 = 0x0603;
pub const OP_NOTIFICATION_CLEAR: u16 = 0x0604;
pub const OP_NOTIFICATION_SETTINGS_SNAPSHOT: u16 = 0x0605;
pub const OP_NOTIFICATION_FOCUS_SET: u16 = 0x0606;
pub const OP_NOTIFICATION_APPLICATION_SET: u16 = 0x0607;

pub const OP_STATUS: u16 = 0x8000;
pub const OP_CLIPBOARD_METADATA: u16 = 0x8103;
pub const OP_CLIPBOARD_CHUNK: u16 = 0x8104;
pub const OP_ASSOCIATION_RESULT: u16 = 0x8202;
pub const OP_ASSOCIATION_HANDLERS_RESULT: u16 = 0x8204;
pub const OP_FILE_PANEL_RESULT: u16 = 0x8300;
pub const OP_FILE_PANEL_OPERATION_ERROR: u16 = 0x8302;
pub const OP_CONTROL_CENTER_CARD_SNAPSHOT_RESULT: u16 = 0x8501;
pub const OP_NOTIFICATION_SNAPSHOT_RESULT: u16 = 0x8601;
pub const OP_NOTIFICATION_SETTINGS_SNAPSHOT_RESULT: u16 = 0x8605;

pub const FILE_PANEL_MODE_OPEN: u16 = 1;
pub const FILE_PANEL_MODE_SAVE: u16 = 2;
pub const FILE_PANEL_REQUEST_PREFIX_LEN: usize = 16;
pub const FILE_PANEL_RESULT_PREFIX_LEN: usize = 24;
pub const FILE_PANEL_TOKEN_LEN: usize = 16;
pub const FILE_PANEL_FINISH_PREFIX_LEN: usize = 24;
pub const MAX_FILE_PANEL_ERROR_LEN: usize = 1023;
pub const MAX_FILE_PANEL_TITLE_LEN: usize = 255;
pub const MAX_FILE_PANEL_SUGGESTED_NAME_LEN: usize = 255;
pub const MAX_FILE_PANEL_CONTENT_TYPES_LEN: usize = 2047;

pub const ASSOCIATION_ROLE_VIEW: u16 = 1 << 0;
pub const ASSOCIATION_ROLE_EDIT: u16 = 1 << 1;
pub const ASSOCIATION_ROLE_ALL: u16 = ASSOCIATION_ROLE_VIEW | ASSOCIATION_ROLE_EDIT;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    BufferTooSmall,
    InvalidMagic,
    UnsupportedVersion,
    InvalidLength,
    InvalidField,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message<'a> {
    pub opcode: u16,
    pub request_id: u64,
    pub flags: u32,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DocumentDelivery<'a> {
    pub path: &'a str,
    pub content_type: &'a str,
}

pub fn encode_document_delivery(
    path: &str,
    content_type: &str,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    if path.is_empty()
        || path.len() > MAX_PATH_LEN
        || content_type.is_empty()
        || content_type.len() > MAX_CONTENT_TYPE_LEN
        || path.as_bytes().contains(&0)
        || content_type.as_bytes().contains(&0)
    {
        return Err(ProtocolError::InvalidField);
    }
    let length = DOCUMENT_DELIVERY_PREFIX_LEN
        .checked_add(path.len())
        .and_then(|value| value.checked_add(content_type.len()))
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < length {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..length].fill(0);
    output[..8].copy_from_slice(&DOCUMENT_DELIVERY_MAGIC);
    output[8..10].copy_from_slice(&(path.len() as u16).to_le_bytes());
    output[10..12].copy_from_slice(&(content_type.len() as u16).to_le_bytes());
    output[DOCUMENT_DELIVERY_PREFIX_LEN..DOCUMENT_DELIVERY_PREFIX_LEN + path.len()]
        .copy_from_slice(path.as_bytes());
    output[DOCUMENT_DELIVERY_PREFIX_LEN + path.len()..length]
        .copy_from_slice(content_type.as_bytes());
    Ok(length)
}

pub fn decode_document_delivery(input: &[u8]) -> Result<DocumentDelivery<'_>, ProtocolError> {
    if input.len() < DOCUMENT_DELIVERY_PREFIX_LEN
        || input[..8] != DOCUMENT_DELIVERY_MAGIC
        || input[12..16] != [0; 4]
    {
        return Err(ProtocolError::InvalidField);
    }
    let path_len = u16::from_le_bytes([input[8], input[9]]) as usize;
    let content_type_len = u16::from_le_bytes([input[10], input[11]]) as usize;
    let length = DOCUMENT_DELIVERY_PREFIX_LEN
        .checked_add(path_len)
        .and_then(|value| value.checked_add(content_type_len))
        .ok_or(ProtocolError::InvalidLength)?;
    if length != input.len() || path_len == 0 || content_type_len == 0 {
        return Err(ProtocolError::InvalidLength);
    }
    let path = core::str::from_utf8(
        &input[DOCUMENT_DELIVERY_PREFIX_LEN..DOCUMENT_DELIVERY_PREFIX_LEN + path_len],
    )
    .map_err(|_| ProtocolError::InvalidField)?;
    let content_type = core::str::from_utf8(&input[DOCUMENT_DELIVERY_PREFIX_LEN + path_len..])
        .map_err(|_| ProtocolError::InvalidField)?;
    if path.len() > MAX_PATH_LEN
        || content_type.len() > MAX_CONTENT_TYPE_LEN
        || path.as_bytes().contains(&0)
        || content_type.as_bytes().contains(&0)
    {
        return Err(ProtocolError::InvalidField);
    }
    Ok(DocumentDelivery { path, content_type })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilePanelRequest<'a> {
    pub mode: u16,
    pub title: &'a str,
    pub initial_directory: &'a str,
    pub suggested_name: &'a str,
    /// ASCII content types separated by the unit-separator byte (`0x1f`).
    pub allowed_content_types: &'a str,
    pub executable: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilePanelResult<'a> {
    pub status: i32,
    pub token: [u8; FILE_PANEL_TOKEN_LEN],
    pub path: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilePanelFinish<'a> {
    pub token: [u8; FILE_PANEL_TOKEN_LEN],
    /// Zero means the selected path was used successfully. One means the
    /// application operation failed and the picker must remain open.
    pub status: i32,
    pub error: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlCenterCard<'a> {
    pub bundle_id: &'a str,
    pub item_id: &'a str,
    pub title: &'a str,
    /// Newline-separated rows. Each row is `label\x1fvalue`.
    pub body: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Notification<'a> {
    pub id: u64,
    pub created_at: u64,
    pub read: bool,
    pub bundle_id: &'a str,
    pub title: &'a str,
    pub body: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotificationSettings<'a> {
    pub focus_enabled: bool,
    /// Newline-separated bundle identifiers whose notifications are disabled.
    pub disabled_bundle_ids: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotificationApplicationSetting<'a> {
    pub enabled: bool,
    pub bundle_id: &'a str,
}

pub fn encode_notification_settings(
    settings: NotificationSettings<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let identifiers = settings.disabled_bundle_ids.as_bytes();
    let total = 4usize
        .checked_add(identifiers.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total || total > MAX_NOTIFICATION_SETTINGS_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if settings.disabled_bundle_ids.lines().any(|bundle_id| {
        bundle_id.is_empty()
            || bundle_id.len() > MAX_BUNDLE_ID_LEN
            || bundle_id.chars().any(char::is_control)
    }) {
        return Err(ProtocolError::InvalidField);
    }
    output[0] = u8::from(settings.focus_enabled);
    output[1..4].fill(0);
    output[4..total].copy_from_slice(identifiers);
    Ok(total)
}

pub fn decode_notification_settings(
    payload: &[u8],
) -> Result<NotificationSettings<'_>, ProtocolError> {
    if payload.len() < 4
        || payload.len() > MAX_NOTIFICATION_SETTINGS_LEN
        || payload[0] > 1
        || payload[1..4] != [0; 3]
    {
        return Err(ProtocolError::InvalidField);
    }
    let disabled_bundle_ids =
        core::str::from_utf8(&payload[4..]).map_err(|_| ProtocolError::InvalidField)?;
    if disabled_bundle_ids.lines().any(|bundle_id| {
        bundle_id.is_empty()
            || bundle_id.len() > MAX_BUNDLE_ID_LEN
            || bundle_id.chars().any(char::is_control)
    }) {
        return Err(ProtocolError::InvalidField);
    }
    Ok(NotificationSettings {
        focus_enabled: payload[0] != 0,
        disabled_bundle_ids,
    })
}

pub fn encode_notification_application_setting(
    setting: NotificationApplicationSetting<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let total = 1usize
        .checked_add(setting.bundle_id.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    if setting.bundle_id.is_empty()
        || setting.bundle_id.len() > MAX_BUNDLE_ID_LEN
        || setting.bundle_id.chars().any(char::is_control)
    {
        return Err(ProtocolError::InvalidField);
    }
    output[0] = u8::from(setting.enabled);
    output[1..total].copy_from_slice(setting.bundle_id.as_bytes());
    Ok(total)
}

pub fn decode_notification_application_setting(
    payload: &[u8],
) -> Result<NotificationApplicationSetting<'_>, ProtocolError> {
    if payload.is_empty() || payload[0] > 1 {
        return Err(ProtocolError::InvalidField);
    }
    let bundle_id = core::str::from_utf8(&payload[1..]).map_err(|_| ProtocolError::InvalidField)?;
    if bundle_id.is_empty()
        || bundle_id.len() > MAX_BUNDLE_ID_LEN
        || bundle_id.chars().any(char::is_control)
    {
        return Err(ProtocolError::InvalidField);
    }
    Ok(NotificationApplicationSetting {
        enabled: payload[0] != 0,
        bundle_id,
    })
}

pub fn encode_notification(
    notification: Notification<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let fields = [
        notification.bundle_id.as_bytes(),
        notification.title.as_bytes(),
        notification.body.as_bytes(),
    ];
    let limits = [
        MAX_BUNDLE_ID_LEN,
        MAX_NOTIFICATION_TITLE_LEN,
        MAX_NOTIFICATION_BODY_LEN,
    ];
    if fields
        .iter()
        .zip(limits)
        .any(|(field, limit)| field.is_empty() || field.len() > limit)
    {
        return Err(ProtocolError::InvalidField);
    }
    let total = fields
        .iter()
        .try_fold(NOTIFICATION_PREFIX_LEN, |total, field| {
            total
                .checked_add(field.len())
                .ok_or(ProtocolError::InvalidLength)
        })?;
    if output.len() < total || total > MAX_MESSAGE_LEN - HEADER_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..8].copy_from_slice(&notification.id.to_le_bytes());
    output[8..16].copy_from_slice(&notification.created_at.to_le_bytes());
    output[16] = u8::from(notification.read);
    output[17] = 0;
    for (index, field) in fields.iter().enumerate() {
        output[18 + index * 2..20 + index * 2].copy_from_slice(
            &u16::try_from(field.len())
                .map_err(|_| ProtocolError::InvalidLength)?
                .to_le_bytes(),
        );
    }
    let mut offset = NOTIFICATION_PREFIX_LEN;
    for field in fields {
        output[offset..offset + field.len()].copy_from_slice(field);
        offset += field.len();
    }
    decode_notification(&output[..total])?;
    Ok(total)
}

pub fn decode_notification(payload: &[u8]) -> Result<Notification<'_>, ProtocolError> {
    if payload.len() < NOTIFICATION_PREFIX_LEN || payload[16] > 1 || payload[17] != 0 {
        return Err(ProtocolError::InvalidField);
    }
    let lengths = [
        read_u16(payload, 18)? as usize,
        read_u16(payload, 20)? as usize,
        read_u16(payload, 22)? as usize,
    ];
    let limits = [
        MAX_BUNDLE_ID_LEN,
        MAX_NOTIFICATION_TITLE_LEN,
        MAX_NOTIFICATION_BODY_LEN,
    ];
    let expected = lengths
        .iter()
        .try_fold(NOTIFICATION_PREFIX_LEN, |total, length| {
            total
                .checked_add(*length)
                .ok_or(ProtocolError::InvalidLength)
        })?;
    if expected != payload.len() {
        return Err(ProtocolError::InvalidLength);
    }
    let mut offset = NOTIFICATION_PREFIX_LEN;
    let mut next = |index: usize| {
        let length = lengths[index];
        let value = validate_utf8_field(payload, offset, length, limits[index])?;
        offset += length;
        Ok(value)
    };
    Ok(Notification {
        id: read_u64(payload, 0)?,
        created_at: read_u64(payload, 8)?,
        read: payload[16] != 0,
        bundle_id: next(0)?,
        title: next(1)?,
        body: next(2)?,
    })
}

pub fn encode_control_center_card(
    card: ControlCenterCard<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let fields = [
        card.bundle_id.as_bytes(),
        card.item_id.as_bytes(),
        card.title.as_bytes(),
        card.body.as_bytes(),
    ];
    let limits = [
        MAX_BUNDLE_ID_LEN,
        MAX_CONTROL_CENTER_ITEM_ID_LEN,
        MAX_CONTROL_CENTER_CARD_TITLE_LEN,
        MAX_CONTROL_CENTER_CARD_BODY_LEN,
    ];
    if fields
        .iter()
        .zip(limits)
        .any(|(field, limit)| field.is_empty() || field.len() > limit)
    {
        return Err(ProtocolError::InvalidField);
    }
    let total = fields
        .iter()
        .try_fold(CONTROL_CENTER_CARD_PREFIX_LEN, |total, field| {
            total
                .checked_add(field.len())
                .ok_or(ProtocolError::InvalidLength)
        })?;
    if output.len() < total || total > MAX_MESSAGE_LEN - HEADER_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    for (index, field) in fields.iter().enumerate() {
        output[index * 2..index * 2 + 2].copy_from_slice(
            &u16::try_from(field.len())
                .map_err(|_| ProtocolError::InvalidLength)?
                .to_le_bytes(),
        );
    }
    let mut offset = CONTROL_CENTER_CARD_PREFIX_LEN;
    for field in fields {
        output[offset..offset + field.len()].copy_from_slice(field);
        offset += field.len();
    }
    decode_control_center_card(&output[..total])?;
    Ok(total)
}

pub fn decode_control_center_card(payload: &[u8]) -> Result<ControlCenterCard<'_>, ProtocolError> {
    if payload.len() < CONTROL_CENTER_CARD_PREFIX_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    let lengths = [
        read_u16(payload, 0)? as usize,
        read_u16(payload, 2)? as usize,
        read_u16(payload, 4)? as usize,
        read_u16(payload, 6)? as usize,
    ];
    let limits = [
        MAX_BUNDLE_ID_LEN,
        MAX_CONTROL_CENTER_ITEM_ID_LEN,
        MAX_CONTROL_CENTER_CARD_TITLE_LEN,
        MAX_CONTROL_CENTER_CARD_BODY_LEN,
    ];
    let expected = lengths
        .iter()
        .try_fold(CONTROL_CENTER_CARD_PREFIX_LEN, |total, length| {
            total
                .checked_add(*length)
                .ok_or(ProtocolError::InvalidLength)
        })?;
    if expected != payload.len() {
        return Err(ProtocolError::InvalidLength);
    }
    let mut offset = CONTROL_CENTER_CARD_PREFIX_LEN;
    let mut next = |index: usize| {
        let length = lengths[index];
        let value = validate_utf8_field(payload, offset, length, limits[index])?;
        offset += length;
        Ok(value)
    };
    Ok(ControlCenterCard {
        bundle_id: next(0)?,
        item_id: next(1)?,
        title: next(2)?,
        body: next(3)?,
    })
}

pub fn decode_file_panel_finish(payload: &[u8]) -> Result<FilePanelFinish<'_>, ProtocolError> {
    if payload.len() < FILE_PANEL_FINISH_PREFIX_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    let mut token = [0; FILE_PANEL_TOKEN_LEN];
    token.copy_from_slice(&payload[..FILE_PANEL_TOKEN_LEN]);
    let status = read_i32(payload, 16)?;
    let error_len = read_u16(payload, 20)? as usize;
    if !matches!(status, 0 | 1)
        || read_u16(payload, 22)? != 0
        || error_len > MAX_FILE_PANEL_ERROR_LEN
        || payload.len() != FILE_PANEL_FINISH_PREFIX_LEN + error_len
        || (status == 0 && error_len != 0)
    {
        return Err(ProtocolError::InvalidField);
    }
    let error = core::str::from_utf8(&payload[FILE_PANEL_FINISH_PREFIX_LEN..])
        .map_err(|_| ProtocolError::InvalidField)?;
    Ok(FilePanelFinish {
        token,
        status,
        error,
    })
}

pub fn encode_file_panel_finish(
    finish: FilePanelFinish<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let total = FILE_PANEL_FINISH_PREFIX_LEN
        .checked_add(finish.error.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total
        || !matches!(finish.status, 0 | 1)
        || finish.error.len() > MAX_FILE_PANEL_ERROR_LEN
        || (finish.status == 0 && !finish.error.is_empty())
    {
        return Err(if output.len() < total {
            ProtocolError::BufferTooSmall
        } else {
            ProtocolError::InvalidField
        });
    }
    output[..FILE_PANEL_TOKEN_LEN].copy_from_slice(&finish.token);
    output[16..20].copy_from_slice(&finish.status.to_le_bytes());
    output[20..22].copy_from_slice(
        &u16::try_from(finish.error.len())
            .map_err(|_| ProtocolError::InvalidLength)?
            .to_le_bytes(),
    );
    output[22..24].fill(0);
    output[24..total].copy_from_slice(finish.error.as_bytes());
    decode_file_panel_finish(&output[..total])?;
    Ok(total)
}

pub fn decode_file_panel_request(payload: &[u8]) -> Result<FilePanelRequest<'_>, ProtocolError> {
    if payload.len() < FILE_PANEL_REQUEST_PREFIX_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    let mode = read_u16(payload, 0)?;
    let lengths = [
        read_u16(payload, 2)? as usize,
        read_u16(payload, 4)? as usize,
        read_u16(payload, 6)? as usize,
        read_u16(payload, 8)? as usize,
        read_u16(payload, 10)? as usize,
    ];
    if read_u32(payload, 12)? != 0
        || !matches!(mode, FILE_PANEL_MODE_OPEN | FILE_PANEL_MODE_SAVE)
        || lengths[0] > MAX_FILE_PANEL_TITLE_LEN
        || lengths[1] > MAX_PATH_LEN
        || lengths[2] > MAX_FILE_PANEL_SUGGESTED_NAME_LEN
        || lengths[3] > MAX_FILE_PANEL_CONTENT_TYPES_LEN
        || lengths[4] == 0
        || lengths[4] > MAX_PATH_LEN
    {
        return Err(ProtocolError::InvalidField);
    }
    let expected = lengths
        .iter()
        .try_fold(FILE_PANEL_REQUEST_PREFIX_LEN, |total, length| {
            total
                .checked_add(*length)
                .ok_or(ProtocolError::InvalidLength)
        })?;
    if expected != payload.len() {
        return Err(ProtocolError::InvalidLength);
    }
    let mut offset = FILE_PANEL_REQUEST_PREFIX_LEN;
    let mut next = |length: usize, maximum: usize, allow_empty: bool| {
        let value = payload
            .get(offset..offset + length)
            .ok_or(ProtocolError::InvalidLength)?;
        offset += length;
        if (!allow_empty && value.is_empty()) || value.len() > maximum {
            return Err(ProtocolError::InvalidField);
        }
        core::str::from_utf8(value).map_err(|_| ProtocolError::InvalidField)
    };
    let title = next(lengths[0], MAX_FILE_PANEL_TITLE_LEN, true)?;
    let initial_directory = next(lengths[1], MAX_PATH_LEN, true)?;
    let suggested_name = next(lengths[2], MAX_FILE_PANEL_SUGGESTED_NAME_LEN, true)?;
    let allowed_content_types = next(lengths[3], MAX_FILE_PANEL_CONTENT_TYPES_LEN, true)?;
    let executable = next(lengths[4], MAX_PATH_LEN, false)?;
    if mode == FILE_PANEL_MODE_OPEN && !suggested_name.is_empty() {
        return Err(ProtocolError::InvalidField);
    }
    Ok(FilePanelRequest {
        mode,
        title,
        initial_directory,
        suggested_name,
        allowed_content_types,
        executable,
    })
}

pub fn encode_file_panel_request(
    request: FilePanelRequest<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let fields = [
        request.title.as_bytes(),
        request.initial_directory.as_bytes(),
        request.suggested_name.as_bytes(),
        request.allowed_content_types.as_bytes(),
        request.executable.as_bytes(),
    ];
    let payload_len = fields
        .iter()
        .try_fold(FILE_PANEL_REQUEST_PREFIX_LEN, |total, field| {
            total
                .checked_add(field.len())
                .ok_or(ProtocolError::InvalidLength)
        })?;
    if payload_len > MAX_MESSAGE_LEN - HEADER_LEN || output.len() < payload_len {
        return Err(ProtocolError::BufferTooSmall);
    }
    let payload = &mut output[..payload_len];
    payload[..2].copy_from_slice(&request.mode.to_le_bytes());
    for (index, field) in fields.iter().enumerate() {
        let length = u16::try_from(field.len()).map_err(|_| ProtocolError::InvalidLength)?;
        let start = 2 + index * 2;
        payload[start..start + 2].copy_from_slice(&length.to_le_bytes());
    }
    payload[12..16].fill(0);
    let mut offset = FILE_PANEL_REQUEST_PREFIX_LEN;
    for field in fields {
        payload[offset..offset + field.len()].copy_from_slice(field);
        offset += field.len();
    }
    decode_file_panel_request(payload)?;
    Ok(payload_len)
}

pub fn decode_file_panel_result(payload: &[u8]) -> Result<FilePanelResult<'_>, ProtocolError> {
    if payload.len() < FILE_PANEL_RESULT_PREFIX_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    let status = read_i32(payload, 0)?;
    let path_len = read_u16(payload, 4)? as usize;
    if read_u16(payload, 6)? != 0
        || path_len > MAX_PATH_LEN
        || payload.len() != FILE_PANEL_RESULT_PREFIX_LEN + path_len
        || (status == 0) != (path_len != 0)
    {
        return Err(ProtocolError::InvalidField);
    }
    let mut token = [0; FILE_PANEL_TOKEN_LEN];
    token.copy_from_slice(&payload[8..24]);
    let path = core::str::from_utf8(&payload[24..]).map_err(|_| ProtocolError::InvalidField)?;
    Ok(FilePanelResult {
        status,
        token,
        path,
    })
}

pub fn encode_file_panel_result(
    result: FilePanelResult<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let total = FILE_PANEL_RESULT_PREFIX_LEN
        .checked_add(result.path.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if total > MAX_MESSAGE_LEN - HEADER_LEN || output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..4].copy_from_slice(&result.status.to_le_bytes());
    output[4..6].copy_from_slice(
        &u16::try_from(result.path.len())
            .map_err(|_| ProtocolError::InvalidLength)?
            .to_le_bytes(),
    );
    output[6..8].fill(0);
    output[8..24].copy_from_slice(&result.token);
    output[24..total].copy_from_slice(result.path.as_bytes());
    decode_file_panel_result(&output[..total])?;
    Ok(total)
}

pub fn decode(bytes: &[u8]) -> Result<Message<'_>, ProtocolError> {
    if bytes.len() < HEADER_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if bytes[..4] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    let version = read_u16(bytes, 4)?;
    if version != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let payload_len = read_u32(bytes, 16)? as usize;
    let total = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(ProtocolError::InvalidLength)?;
    if total != bytes.len() || total > MAX_MESSAGE_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(Message {
        opcode: read_u16(bytes, 6)?,
        request_id: read_u64(bytes, 8)?,
        flags: read_u32(bytes, 20)?,
        payload: &bytes[HEADER_LEN..total],
    })
}

pub fn encode(
    opcode: u16,
    request_id: u64,
    flags: u32,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let total = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if total > MAX_MESSAGE_LEN || output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..4].copy_from_slice(&MAGIC);
    output[4..6].copy_from_slice(&VERSION.to_le_bytes());
    output[6..8].copy_from_slice(&opcode.to_le_bytes());
    output[8..16].copy_from_slice(&request_id.to_le_bytes());
    output[16..20].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    output[20..24].copy_from_slice(&flags.to_le_bytes());
    output[HEADER_LEN..total].copy_from_slice(payload);
    Ok(total)
}

pub fn encode_status(
    request_id: u64,
    status: i32,
    generation: u64,
    value: u64,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let mut payload = [0u8; 24];
    payload[..4].copy_from_slice(&status.to_le_bytes());
    payload[8..16].copy_from_slice(&generation.to_le_bytes());
    payload[16..24].copy_from_slice(&value.to_le_bytes());
    encode(OP_STATUS, request_id, 0, &payload, output)
}

pub fn decode_status(message: Message<'_>) -> Result<(i32, u64, u64), ProtocolError> {
    if message.opcode != OP_STATUS || message.payload.len() != 24 {
        return Err(ProtocolError::InvalidField);
    }
    Ok((
        read_i32(message.payload, 0)?,
        read_u64(message.payload, 8)?,
        read_u64(message.payload, 16)?,
    ))
}

pub fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ProtocolError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(ProtocolError::InvalidLength)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

pub fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ProtocolError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(ProtocolError::InvalidLength)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

pub fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, ProtocolError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(ProtocolError::InvalidLength)?;
    Ok(i32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

pub fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ProtocolError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(ProtocolError::InvalidLength)?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

pub fn validate_utf8_field<'a>(
    bytes: &'a [u8],
    offset: usize,
    length: usize,
    maximum: usize,
) -> Result<&'a str, ProtocolError> {
    if length == 0 || length > maximum {
        return Err(ProtocolError::InvalidField);
    }
    let field = bytes
        .get(
            offset
                ..offset
                    .checked_add(length)
                    .ok_or(ProtocolError::InvalidLength)?,
        )
        .ok_or(ProtocolError::InvalidLength)?;
    core::str::from_utf8(field).map_err(|_| ProtocolError::InvalidField)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_round_trip_has_stable_little_endian_header() {
        let mut encoded = [0u8; 64];
        let length = encode(
            OP_CLIPBOARD_SNAPSHOT,
            0x0102_0304_0506_0708,
            3,
            b"abc",
            &mut encoded,
        )
        .expect("encode");
        assert_eq!(&encoded[..4], b"MWSP");
        assert_eq!(&encoded[4..8], &[1, 0, 3, 1]);
        assert_eq!(&encoded[8..16], &[8, 7, 6, 5, 4, 3, 2, 1]);
        let decoded = decode(&encoded[..length]).expect("decode");
        assert_eq!(decoded.opcode, OP_CLIPBOARD_SNAPSHOT);
        assert_eq!(decoded.request_id, 0x0102_0304_0506_0708);
        assert_eq!(decoded.flags, 3);
        assert_eq!(decoded.payload, b"abc");
    }

    #[test]
    fn malformed_length_and_unknown_version_are_rejected() {
        let mut encoded = [0u8; 64];
        let length = encode(OP_CLIPBOARD_SNAPSHOT, 1, 0, b"abc", &mut encoded).unwrap();
        encoded[16..20].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            decode(&encoded[..length]),
            Err(ProtocolError::InvalidLength)
        );
        encoded[16..20].copy_from_slice(&3u32.to_le_bytes());
        encoded[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            decode(&encoded[..length]),
            Err(ProtocolError::UnsupportedVersion)
        );
    }

    #[test]
    fn file_panel_payloads_round_trip() {
        let request = FilePanelRequest {
            mode: FILE_PANEL_MODE_SAVE,
            title: "Save As",
            initial_directory: "/home/mochi/Documents",
            suggested_name: "note.txt",
            allowed_content_types: "text/plain\x1fapplication/json",
            executable: "/applications/Edit.app/entry.elf",
        };
        let mut payload = [0u8; 512];
        let length = encode_file_panel_request(request, &mut payload).unwrap();
        assert_eq!(
            decode_file_panel_request(&payload[..length]).unwrap(),
            request
        );

        let result = FilePanelResult {
            status: 0,
            token: [7; FILE_PANEL_TOKEN_LEN],
            path: "/home/mochi/Documents/note.txt",
        };
        let length = encode_file_panel_result(result, &mut payload).unwrap();
        assert_eq!(
            decode_file_panel_result(&payload[..length]).unwrap(),
            result
        );

        let finish = FilePanelFinish {
            token: [9; FILE_PANEL_TOKEN_LEN],
            status: 1,
            error: "Permission denied",
        };
        let length = encode_file_panel_finish(finish, &mut payload).unwrap();
        assert_eq!(
            decode_file_panel_finish(&payload[..length]).unwrap(),
            finish
        );
    }

    #[test]
    fn successful_file_panel_result_requires_a_path() {
        let mut payload = [0u8; FILE_PANEL_RESULT_PREFIX_LEN];
        assert_eq!(
            encode_file_panel_result(
                FilePanelResult {
                    status: 0,
                    token: [0; FILE_PANEL_TOKEN_LEN],
                    path: "",
                },
                &mut payload,
            ),
            Err(ProtocolError::InvalidField)
        );
    }

    #[test]
    fn control_center_card_round_trip() {
        let card = ControlCenterCard {
            bundle_id: "org.mochios.example",
            item_id: "status",
            title: "Example Status",
            body: "State\x1fReady\nVersion\x1f1.0",
        };
        let mut payload = [0u8; 256];
        let length = encode_control_center_card(card, &mut payload).unwrap();
        assert_eq!(decode_control_center_card(&payload[..length]), Ok(card));
        assert_eq!(
            decode_control_center_card(&payload[..length - 1]),
            Err(ProtocolError::InvalidLength)
        );
    }

    #[test]
    fn notification_round_trip() {
        let notification = Notification {
            id: 42,
            created_at: 900,
            read: true,
            bundle_id: "org.mochios.example",
            title: "Export complete",
            body: "The document is ready.",
        };
        let mut payload = [0u8; 512];
        let length = encode_notification(notification, &mut payload).unwrap();
        assert_eq!(decode_notification(&payload[..length]), Ok(notification));
        assert_eq!(
            decode_notification(&payload[..length - 1]),
            Err(ProtocolError::InvalidLength)
        );
    }

    #[test]
    fn notification_settings_round_trip() {
        let settings = NotificationSettings {
            focus_enabled: true,
            disabled_bundle_ids: "org.mochios.mail\norg.mochios.test",
        };
        let mut payload = [0u8; 256];
        let length = encode_notification_settings(settings, &mut payload).unwrap();
        assert_eq!(
            decode_notification_settings(&payload[..length]),
            Ok(settings)
        );

        let application = NotificationApplicationSetting {
            enabled: false,
            bundle_id: "org.mochios.test",
        };
        let length = encode_notification_application_setting(application, &mut payload).unwrap();
        assert_eq!(
            decode_notification_application_setting(&payload[..length]),
            Ok(application)
        );
    }
}
