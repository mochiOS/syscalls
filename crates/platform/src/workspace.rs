use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use mochios_workspace_protocol as protocol;

use crate::syscall::{self, SysError, SysResult};

const SERVICE_NAME: &str = "workspace.service";
const TEXT_CONTENT_TYPE: &str = "text/plain;charset=utf-8";
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

pub const ASSOCIATION_ROLE_VIEW: u16 = protocol::ASSOCIATION_ROLE_VIEW;
pub const ASSOCIATION_ROLE_EDIT: u16 = protocol::ASSOCIATION_ROLE_EDIT;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssociationHandler {
    pub bundle_id: String,
    pub name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilePanelMode {
    Open,
    Save,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilePanelOptions<'a> {
    pub mode: FilePanelMode,
    pub title: &'a str,
    pub initial_directory: &'a str,
    pub suggested_name: &'a str,
    pub allowed_content_types: &'a [&'a str],
    pub executable: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilePanelSelection {
    pub token: [u8; protocol::FILE_PANEL_TOKEN_LEN],
    pub path: String,
}

fn invalid() -> SysError {
    SysError::from_raw(syscall::EINVAL as i64)
}

fn request_id() -> u64 {
    NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed).max(1)
}

fn service() -> SysResult<u64> {
    for _ in 0..32 {
        if let Ok(service) = crate::process::find_by_name(SERVICE_NAME) {
            return Ok(service);
        }
        crate::thread::yield_now();
    }
    crate::process::find_by_name(SERVICE_NAME)
}

fn call<'a>(opcode: u16, payload: &[u8], reply: &'a mut [u8]) -> SysResult<protocol::Message<'a>> {
    let id = request_id();
    let mut request = vec![0u8; protocol::HEADER_LEN + payload.len()];
    let length = protocol::encode(opcode, id, 0, payload, &mut request).map_err(|_| invalid())?;
    let received = crate::ipc::call(service()?, &request[..length], reply)? as usize;
    let message =
        protocol::decode(reply.get(..received).ok_or_else(invalid)?).map_err(|_| invalid())?;
    if message.request_id != id {
        return Err(invalid());
    }
    Ok(message)
}

fn status(message: protocol::Message<'_>) -> SysResult<(u64, u64)> {
    let (status, generation, value) = protocol::decode_status(message).map_err(|_| invalid())?;
    if status != 0 {
        return Err(SysError::from_raw(status.unsigned_abs() as i64));
    }
    Ok((generation, value))
}

pub fn register_application(endpoint: u64) -> SysResult<()> {
    let mut reply = [0u8; protocol::HEADER_LEN + 24];
    status(call(
        protocol::OP_APPLICATION_REGISTER,
        &endpoint.to_le_bytes(),
        &mut reply,
    )?)?;
    Ok(())
}

pub fn activate_application(process_id: u64) -> SysResult<()> {
    let mut reply = [0u8; protocol::HEADER_LEN + 24];
    status(call(
        protocol::OP_APPLICATION_ACTIVATE,
        &process_id.to_le_bytes(),
        &mut reply,
    )?)?;
    Ok(())
}

pub fn set_clipboard(content_type: &str, bytes: &[u8]) -> SysResult<()> {
    if content_type.is_empty()
        || content_type.len() > protocol::MAX_CONTENT_TYPE_LEN
        || bytes.len() > protocol::MAX_CLIPBOARD_BYTES
    {
        return Err(invalid());
    }
    let mut begin = Vec::with_capacity(16 + content_type.len());
    begin.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    begin.extend_from_slice(&(content_type.len() as u16).to_le_bytes());
    begin.extend_from_slice(&[0; 6]);
    begin.extend_from_slice(content_type.as_bytes());
    let mut small_reply = [0u8; protocol::HEADER_LEN + 24];
    let (_, transaction) = status(call(
        protocol::OP_CLIPBOARD_SET_BEGIN,
        &begin,
        &mut small_reply,
    )?)?;

    for (index, chunk) in bytes.chunks(protocol::MAX_CHUNK_BYTES).enumerate() {
        let offset = index.saturating_mul(protocol::MAX_CHUNK_BYTES);
        let mut payload = Vec::with_capacity(16 + chunk.len());
        payload.extend_from_slice(&transaction.to_le_bytes());
        payload.extend_from_slice(&(offset as u64).to_le_bytes());
        payload.extend_from_slice(chunk);
        status(call(
            protocol::OP_CLIPBOARD_SET_CHUNK,
            &payload,
            &mut small_reply,
        )?)?;
    }

    let transaction = transaction.to_le_bytes();
    status(call(
        protocol::OP_CLIPBOARD_SET_COMMIT,
        &transaction,
        &mut small_reply,
    )?)?;
    Ok(())
}

pub fn set_clipboard_text(text: &str) -> SysResult<()> {
    set_clipboard(TEXT_CONTENT_TYPE, text.as_bytes())
}

pub fn clipboard() -> SysResult<Option<(String, Vec<u8>)>> {
    let mut metadata_reply = vec![0u8; protocol::MAX_MESSAGE_LEN];
    let metadata = call(protocol::OP_CLIPBOARD_SNAPSHOT, &[], &mut metadata_reply)?;
    if metadata.opcode != protocol::OP_CLIPBOARD_METADATA || metadata.payload.len() < 24 {
        return Err(invalid());
    }
    let generation = protocol::read_u64(metadata.payload, 0).map_err(|_| invalid())?;
    let total = usize::try_from(protocol::read_u64(metadata.payload, 8).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let content_type_len =
        protocol::read_u16(metadata.payload, 16).map_err(|_| invalid())? as usize;
    if total > protocol::MAX_CLIPBOARD_BYTES || metadata.payload.len() != 24 + content_type_len {
        return Err(invalid());
    }
    if generation == 0 {
        return Ok(None);
    }
    let content_type = core::str::from_utf8(&metadata.payload[24..])
        .map_err(|_| invalid())?
        .to_string();
    let mut bytes = Vec::with_capacity(total);
    let mut reply = vec![0u8; protocol::MAX_MESSAGE_LEN];
    while bytes.len() < total {
        let wanted = (total - bytes.len()).min(protocol::MAX_CHUNK_BYTES);
        let mut payload = [0u8; 24];
        payload[..8].copy_from_slice(&generation.to_le_bytes());
        payload[8..16].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
        payload[16..20].copy_from_slice(&(wanted as u32).to_le_bytes());
        let chunk = call(protocol::OP_CLIPBOARD_READ, &payload, &mut reply)?;
        if chunk.opcode != protocol::OP_CLIPBOARD_CHUNK || chunk.payload.len() < 16 {
            return Err(invalid());
        }
        if protocol::read_u64(chunk.payload, 0).map_err(|_| invalid())? != generation
            || protocol::read_u64(chunk.payload, 8).map_err(|_| invalid())? != bytes.len() as u64
            || chunk.payload.len() == 16
        {
            return Err(invalid());
        }
        bytes.extend_from_slice(&chunk.payload[16..]);
    }
    Ok(Some((content_type, bytes)))
}

pub fn clipboard_text() -> SysResult<Option<String>> {
    let Some((content_type, bytes)) = clipboard()? else {
        return Ok(None);
    };
    if !content_type.eq_ignore_ascii_case(TEXT_CONTENT_TYPE)
        && !content_type.eq_ignore_ascii_case("text/plain")
    {
        return Ok(None);
    }
    String::from_utf8(bytes).map(Some).map_err(|_| invalid())
}

pub fn set_association(
    extension: &str,
    content_type: &str,
    bundle_id: &str,
    roles: u16,
) -> SysResult<()> {
    validate_association_key(extension, content_type, roles)?;
    if bundle_id.is_empty() || bundle_id.len() > protocol::MAX_BUNDLE_ID_LEN {
        return Err(invalid());
    }
    let mut payload =
        Vec::with_capacity(8 + extension.len() + content_type.len() + bundle_id.len());
    payload.extend_from_slice(&roles.to_le_bytes());
    payload.extend_from_slice(&(extension.len() as u16).to_le_bytes());
    payload.extend_from_slice(&(content_type.len() as u16).to_le_bytes());
    payload.extend_from_slice(&(bundle_id.len() as u16).to_le_bytes());
    payload.extend_from_slice(extension.as_bytes());
    payload.extend_from_slice(content_type.as_bytes());
    payload.extend_from_slice(bundle_id.as_bytes());
    let mut reply = [0u8; protocol::HEADER_LEN + 24];
    status(call(protocol::OP_ASSOCIATION_SET, &payload, &mut reply)?)?;
    Ok(())
}

pub fn remove_association(extension: &str, content_type: &str, roles: u16) -> SysResult<()> {
    validate_association_key(extension, content_type, roles)?;
    let payload = association_key(extension, content_type, roles);
    let mut reply = [0u8; protocol::HEADER_LEN + 24];
    status(call(protocol::OP_ASSOCIATION_REMOVE, &payload, &mut reply)?)?;
    Ok(())
}

pub fn resolve_association(extension: &str, content_type: &str, roles: u16) -> SysResult<String> {
    validate_association_key(extension, content_type, roles)?;
    let payload = association_key(extension, content_type, roles);
    let mut reply = vec![0u8; protocol::MAX_MESSAGE_LEN];
    let result = call(protocol::OP_ASSOCIATION_RESOLVE, &payload, &mut reply)?;
    if result.opcode == protocol::OP_STATUS {
        status(result)?;
        return Err(invalid());
    }
    if result.opcode != protocol::OP_ASSOCIATION_RESULT || result.payload.len() < 8 {
        return Err(invalid());
    }
    let bundle_len = protocol::read_u16(result.payload, 2).map_err(|_| invalid())? as usize;
    if result.payload.len() != 8 + bundle_len {
        return Err(invalid());
    }
    core::str::from_utf8(&result.payload[8..])
        .map(str::to_string)
        .map_err(|_| invalid())
}

pub fn association_handlers(
    extension: &str,
    content_type: &str,
    roles: u16,
) -> SysResult<Vec<AssociationHandler>> {
    validate_association_key(extension, content_type, roles)?;
    let payload = association_key(extension, content_type, roles);
    let mut reply = vec![0u8; protocol::MAX_MESSAGE_LEN];
    let result = call(protocol::OP_ASSOCIATION_HANDLERS, &payload, &mut reply)?;
    if result.opcode == protocol::OP_STATUS {
        status(result)?;
        return Err(invalid());
    }
    if result.opcode != protocol::OP_ASSOCIATION_HANDLERS_RESULT || result.payload.len() < 8 {
        return Err(invalid());
    }
    let count = protocol::read_u16(result.payload, 0).map_err(|_| invalid())? as usize;
    if count > protocol::MAX_ASSOCIATION_HANDLERS {
        return Err(invalid());
    }
    let mut offset = 8usize;
    let mut handlers = Vec::with_capacity(count);
    for _ in 0..count {
        let bundle_len =
            protocol::read_u16(result.payload, offset).map_err(|_| invalid())? as usize;
        let name_len =
            protocol::read_u16(result.payload, offset + 2).map_err(|_| invalid())? as usize;
        offset = offset.checked_add(4).ok_or_else(invalid)?;
        let end = offset
            .checked_add(bundle_len)
            .and_then(|value| value.checked_add(name_len))
            .ok_or_else(invalid)?;
        let bytes = result.payload.get(offset..end).ok_or_else(invalid)?;
        let bundle_id = core::str::from_utf8(&bytes[..bundle_len])
            .map_err(|_| invalid())?
            .to_string();
        let name = core::str::from_utf8(&bytes[bundle_len..])
            .map_err(|_| invalid())?
            .to_string();
        if bundle_id.is_empty()
            || bundle_id.len() > protocol::MAX_BUNDLE_ID_LEN
            || name.is_empty()
            || name.len() > protocol::MAX_HANDLER_NAME_LEN
        {
            return Err(invalid());
        }
        handlers.push(AssociationHandler { bundle_id, name });
        offset = end;
    }
    if offset != result.payload.len() {
        return Err(invalid());
    }
    Ok(handlers)
}

pub fn open_document(path: &str, content_type: &str, roles: u16) -> SysResult<u64> {
    open_document_with(path, content_type, "", roles)
}

pub fn open_document_with(
    path: &str,
    content_type: &str,
    bundle_id: &str,
    roles: u16,
) -> SysResult<u64> {
    if path.is_empty()
        || path.len() > protocol::MAX_PATH_LEN
        || content_type.is_empty()
        || content_type.len() > protocol::MAX_CONTENT_TYPE_LEN
        || bundle_id.len() > protocol::MAX_BUNDLE_ID_LEN
        || roles == 0
        || roles & !protocol::ASSOCIATION_ROLE_ALL != 0
    {
        return Err(invalid());
    }
    let mut payload = Vec::with_capacity(8 + path.len() + content_type.len() + bundle_id.len());
    payload.extend_from_slice(&roles.to_le_bytes());
    payload.extend_from_slice(&(path.len() as u16).to_le_bytes());
    payload.extend_from_slice(&(content_type.len() as u16).to_le_bytes());
    payload.extend_from_slice(&(bundle_id.len() as u16).to_le_bytes());
    payload.extend_from_slice(path.as_bytes());
    payload.extend_from_slice(content_type.as_bytes());
    payload.extend_from_slice(bundle_id.as_bytes());
    let mut reply = [0u8; protocol::HEADER_LEN + 24];
    let (_, process_id) = status(call(protocol::OP_DOCUMENT_OPEN, &payload, &mut reply)?)?;
    Ok(process_id)
}

/// Starts a workspace-owned file-panel transaction. The returned selection
/// must be acknowledged with [`file_panel_finish`].
pub fn file_panel_begin(options: FilePanelOptions<'_>) -> SysResult<Option<FilePanelSelection>> {
    if options.allowed_content_types.iter().any(|value| {
        value.is_empty()
            || value.len() > protocol::MAX_CONTENT_TYPE_LEN
            || value.as_bytes().contains(&0x1f)
    }) {
        return Err(invalid());
    }
    let content_types = options.allowed_content_types.join("\x1f");
    let request = protocol::FilePanelRequest {
        mode: match options.mode {
            FilePanelMode::Open => protocol::FILE_PANEL_MODE_OPEN,
            FilePanelMode::Save => protocol::FILE_PANEL_MODE_SAVE,
        },
        title: options.title,
        initial_directory: options.initial_directory,
        suggested_name: options.suggested_name,
        allowed_content_types: &content_types,
        executable: options.executable,
    };
    let mut payload = vec![0u8; protocol::MAX_MESSAGE_LEN - protocol::HEADER_LEN];
    let length =
        protocol::encode_file_panel_request(request, &mut payload).map_err(|_| invalid())?;
    let mut reply = vec![0u8; protocol::MAX_MESSAGE_LEN];
    let result = call(protocol::OP_FILE_PANEL, &payload[..length], &mut reply)?;
    if result.opcode == protocol::OP_STATUS {
        status(result)?;
        return Err(invalid());
    }
    if result.opcode != protocol::OP_FILE_PANEL_RESULT {
        return Err(invalid());
    }
    let result = protocol::decode_file_panel_result(result.payload).map_err(|_| invalid())?;
    decode_file_panel_selection(result)
}

fn decode_file_panel_selection(
    result: protocol::FilePanelResult<'_>,
) -> SysResult<Option<FilePanelSelection>> {
    match result.status {
        0 => Ok(Some(FilePanelSelection {
            token: result.token,
            path: result.path.to_string(),
        })),
        1 => Ok(None),
        status => Err(SysError::from_raw(status.unsigned_abs() as i64)),
    }
}

/// Waits for another selection from an existing panel after the application
/// rejected a previous selection.
pub fn file_panel_retry(
    token: [u8; protocol::FILE_PANEL_TOKEN_LEN],
) -> SysResult<Option<FilePanelSelection>> {
    let mut reply = vec![0u8; protocol::MAX_MESSAGE_LEN];
    let result = call(protocol::OP_FILE_PANEL_RETRY, &token, &mut reply)?;
    if result.opcode == protocol::OP_STATUS {
        status(result)?;
        return Err(invalid());
    }
    if result.opcode != protocol::OP_FILE_PANEL_RESULT {
        return Err(invalid());
    }
    decode_file_panel_selection(
        protocol::decode_file_panel_result(result.payload).map_err(|_| invalid())?,
    )
}

/// Reports whether the application operation for a selected path succeeded.
/// A failure keeps the picker open so the user can correct the destination.
pub fn file_panel_finish(
    token: [u8; protocol::FILE_PANEL_TOKEN_LEN],
    succeeded: bool,
) -> SysResult<()> {
    let finish = protocol::FilePanelFinish {
        token,
        status: if succeeded { 0 } else { 1 },
    };
    let mut payload = [0u8; protocol::FILE_PANEL_FINISH_LEN];
    let length = protocol::encode_file_panel_finish(finish, &mut payload).map_err(|_| invalid())?;
    let mut reply = [0u8; protocol::HEADER_LEN + 24];
    status(call(
        protocol::OP_FILE_PANEL_FINISH,
        &payload[..length],
        &mut reply,
    )?)?;
    Ok(())
}

/// Compatibility helper for clients that only select a path and do not run an
/// operation which can fail.
pub fn file_panel(options: FilePanelOptions<'_>) -> SysResult<Option<String>> {
    let Some(selection) = file_panel_begin(options)? else {
        return Ok(None);
    };
    file_panel_finish(selection.token, true)?;
    Ok(Some(selection.path))
}

fn validate_association_key(extension: &str, content_type: &str, roles: u16) -> SysResult<()> {
    if (extension.is_empty() && content_type.is_empty())
        || extension.len() > protocol::MAX_EXTENSION_LEN
        || content_type.len() > protocol::MAX_CONTENT_TYPE_LEN
        || roles == 0
        || roles & !protocol::ASSOCIATION_ROLE_ALL != 0
    {
        return Err(invalid());
    }
    Ok(())
}

fn association_key(extension: &str, content_type: &str, roles: u16) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + extension.len() + content_type.len());
    payload.extend_from_slice(&roles.to_le_bytes());
    payload.extend_from_slice(&(extension.len() as u16).to_le_bytes());
    payload.extend_from_slice(&(content_type.len() as u16).to_le_bytes());
    payload.extend_from_slice(&0u16.to_le_bytes());
    payload.extend_from_slice(extension.as_bytes());
    payload.extend_from_slice(content_type.as_bytes());
    payload
}
