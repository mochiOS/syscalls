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

pub const OP_STATUS: u16 = 0x8000;
pub const OP_CLIPBOARD_METADATA: u16 = 0x8103;
pub const OP_CLIPBOARD_CHUNK: u16 = 0x8104;
pub const OP_ASSOCIATION_RESULT: u16 = 0x8202;
pub const OP_ASSOCIATION_HANDLERS_RESULT: u16 = 0x8204;
pub const OP_FILE_PANEL_RESULT: u16 = 0x8300;

pub const FILE_PANEL_MODE_OPEN: u16 = 1;
pub const FILE_PANEL_MODE_SAVE: u16 = 2;
pub const FILE_PANEL_REQUEST_PREFIX_LEN: usize = 16;
pub const FILE_PANEL_RESULT_PREFIX_LEN: usize = 24;
pub const FILE_PANEL_TOKEN_LEN: usize = 16;
pub const FILE_PANEL_FINISH_LEN: usize = 24;
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
pub struct FilePanelFinish {
    pub token: [u8; FILE_PANEL_TOKEN_LEN],
    /// Zero means the selected path was used successfully. One means the
    /// application operation failed and the picker must remain open.
    pub status: i32,
}

pub fn decode_file_panel_finish(payload: &[u8]) -> Result<FilePanelFinish, ProtocolError> {
    if payload.len() != FILE_PANEL_FINISH_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let mut token = [0; FILE_PANEL_TOKEN_LEN];
    token.copy_from_slice(&payload[..FILE_PANEL_TOKEN_LEN]);
    let status = read_i32(payload, 16)?;
    if !matches!(status, 0 | 1) || read_u32(payload, 20)? != 0 {
        return Err(ProtocolError::InvalidField);
    }
    Ok(FilePanelFinish { token, status })
}

pub fn encode_file_panel_finish(
    finish: FilePanelFinish,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    if output.len() < FILE_PANEL_FINISH_LEN || !matches!(finish.status, 0 | 1) {
        return Err(if output.len() < FILE_PANEL_FINISH_LEN {
            ProtocolError::BufferTooSmall
        } else {
            ProtocolError::InvalidField
        });
    }
    output[..FILE_PANEL_TOKEN_LEN].copy_from_slice(&finish.token);
    output[16..20].copy_from_slice(&finish.status.to_le_bytes());
    output[20..24].fill(0);
    decode_file_panel_finish(&output[..FILE_PANEL_FINISH_LEN])?;
    Ok(FILE_PANEL_FINISH_LEN)
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
}
