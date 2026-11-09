//! Authorized reads of native diagnostic history. This does not open a file
//! or select a persistence policy; the caller owns its cursor and storage.

use crate::syscall::{self, SysError, SysResult};
pub use mnu_abi::diagnostic::{EXIT_KIND_EXCEPTION, EXIT_KIND_STATUS, EXIT_RECORD_LEN, ExitRecord};
pub const IMAGE_METADATA_OPCODE: &[u8; 8] = b"MDIAGIM1";
pub const MAX_IMAGE_METADATA_BYTES: usize = 48 * 1024;

/// Send launcher-owned source/placement metadata alongside an attenuated native
/// Process reference. The receiver authenticates the launcher and the object.
pub fn register_image(process: u32, metadata: &[u8]) -> SysResult<()> {
    use crate::{handle, ipc, memory_object::MemoryObject};
    if metadata.is_empty() || metadata.len() > MAX_IMAGE_METADATA_BYTES {
        return Err(SysError::from_raw(Error::InvalidArgument.into_raw() as i64));
    }
    let endpoint =
        crate::logger::endpoint().ok_or(SysError::from_raw(Error::NotFound.into_raw() as i64))?;
    let peer = crate::execution_peer::capture(endpoint)?;
    let context = &peer.context;
    if context.provenance != 1
        || context.subject_key_id != [0; 32]
        || context.package_id.get(..context.package_id_len as usize) != Some(b"org.mochios.logger")
        || context
            .developer_id
            .get(..context.developer_id_len as usize)
            != Some(b"org.mochios.system")
    {
        return Err(SysError::from_raw(Error::AccessDenied.into_raw() as i64));
    }
    let object = MemoryObject::create(metadata.len() as u64)?;
    let mut offset = 0;
    while offset < metadata.len() {
        let end = metadata.len().min(offset + 4096);
        let count = handle::write_at(object.handle(), &metadata[offset..end], offset as u64)?;
        if count == 0 || count > metadata.len() - offset {
            return Err(SysError::from_raw(Error::BackingFailure.into_raw() as i64));
        }
        offset += count;
    }
    let mut attachments = ipc::IpcObjectHandles::default();
    attachments.count = 2;
    attachments.handles[0] = ipc::IpcObjectHandle {
        handle: process,
        rights: handle::HANDLE_RIGHT_WAIT,
        reserved: 0,
    };
    attachments.handles[1] = ipc::IpcObjectHandle {
        handle: object.handle(),
        rights: handle::HANDLE_RIGHT_READ,
        reserved: 0,
    };
    let mut request = [0; 16];
    request[..8].copy_from_slice(IMAGE_METADATA_OPCODE);
    request[8..].copy_from_slice(&(metadata.len() as u64).to_le_bytes());
    let mut reply = [0; 8];
    let response = ipc::call_object_handles(
        u32::try_from(endpoint)
            .map_err(|_| SysError::from_raw(Error::InvalidArgument.into_raw() as i64))?,
        &request,
        &mut reply,
        &mut attachments,
    );
    for entry in &attachments.handles {
        if entry.handle != 0 && entry.handle != process && entry.handle != object.handle() {
            let _ = handle::close(entry.handle);
        }
    }
    let message = response?;
    if message >> 32 != endpoint
        || message as u32 != 8
        || attachments.count != 0
        || attachments.delivery_flags != 0
    {
        return Err(SysError::from_raw(Error::BackingFailure.into_raw() as i64));
    }
    let status = u64::from_le_bytes(reply);
    if status == 0 {
        Ok(())
    } else {
        Err(SysError::from_raw(status as i64))
    }
}
use mnu_abi::diagnostic::{READ_MAX_BYTES, RESULT_LEN, ReadResult};
use mnu_abi::status::Error;

/// Native abnormal termination records. This stream cannot be written by IPC
/// clients. A nonzero exit status alone does not establish a CPU exception.
pub fn read_exits(cursor: u64, output: &mut [u8]) -> SysResult<(usize, ReadResult)> {
    if output.len() > READ_MAX_BYTES
        || output.len() % EXIT_RECORD_LEN != 0
        || cursor % EXIT_RECORD_LEN as u64 != 0
    {
        return Err(SysError::from_raw(Error::InvalidArgument.into_raw() as i64));
    }
    let mut metadata = [0; RESULT_LEN];
    let copied = syscall::call5(
        syscall::SyscallNumber::DiagnosticStreamRead,
        cursor,
        output.as_mut_ptr() as u64,
        output.len() as u64,
        metadata.as_mut_ptr() as u64,
        mnu_abi::diagnostic::STREAM_PROCESS_EXIT,
    )?;
    let result = ReadResult::from_bytes(&metadata)
        .ok_or(SysError::from_raw(Error::BackingFailure.into_raw() as i64))?;
    if copied > output.len() as u64
        || copied % EXIT_RECORD_LEN as u64 != 0
        || result.dropped % EXIT_RECORD_LEN as u64 != 0
        || cursor
            .checked_add(result.dropped)
            .and_then(|start| start.checked_add(copied))
            != Some(result.next_cursor)
    {
        return Err(SysError::from_raw(Error::BackingFailure.into_raw() as i64));
    }
    Ok((copied as usize, result))
}

pub fn read(cursor: u64, output: &mut [u8]) -> SysResult<(usize, ReadResult)> {
    if output.len() > READ_MAX_BYTES {
        return Err(SysError::from_raw(Error::InvalidArgument.into_raw() as i64));
    }
    let mut metadata = [0; RESULT_LEN];
    let copied = syscall::call4(
        syscall::SyscallNumber::DiagnosticRead,
        cursor,
        output.as_mut_ptr() as u64,
        output.len() as u64,
        metadata.as_mut_ptr() as u64,
    )?;
    let result = ReadResult::from_bytes(&metadata)
        .ok_or(SysError::from_raw(Error::BackingFailure.into_raw() as i64))?;
    if copied > output.len() as u64
        || cursor
            .checked_add(result.dropped)
            .and_then(|start| start.checked_add(copied))
            != Some(result.next_cursor)
    {
        return Err(SysError::from_raw(Error::BackingFailure.into_raw() as i64));
    }
    Ok((copied as usize, result))
}
