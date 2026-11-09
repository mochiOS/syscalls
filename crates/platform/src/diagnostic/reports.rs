//! Read-only snapshots of the current user's private local crash reports.
//! The logger authenticates both the measured reader and POSIX account epoch.
use crate::{
    execution_peer, handle, ipc, process,
    syscall::{self, SysError, SysResult},
};
use alloc::{vec, vec::Vec};

pub const LIST: &[u8; 8] = b"MDIAGLS1";
pub const READ: &[u8; 8] = b"MDIAGRD1";
pub const MAX_SNAPSHOT: usize = 128 * 1024;

pub fn valid_id(id: &str) -> bool {
    let Some(body) = id
        .strip_prefix("crash-")
        .and_then(|s| s.strip_suffix(".json"))
    else {
        return false;
    };
    let bytes = body.as_bytes();
    bytes.len() == 37
        && bytes[16] == b'-'
        && bytes[..16]
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        && bytes[17..].iter().all(u8::is_ascii_digit)
}

pub fn list() -> SysResult<Vec<u8>> {
    request(LIST, "")
}
pub fn read(id: &str) -> SysResult<Vec<u8>> {
    if !valid_id(id) {
        return Err(error(syscall::EINVAL));
    }
    request(READ, id)
}

fn error(raw: u64) -> SysError {
    SysError::from_raw(raw as i64)
}

fn request(opcode: &[u8; 8], id: &str) -> SysResult<Vec<u8>> {
    let endpoint = process::find_by_name("logger.service")?;
    let before = execution_peer::capture_builtin(endpoint, b"org.mochios.logger")?;
    let mut request = Vec::from(opcode.as_slice());
    request.extend_from_slice(id.as_bytes());
    let mut reply = [0; 16];
    let mut attached = ipc::IpcObjectHandles::default();
    let result = (|| {
        let message = ipc::call_object_handles(
            u32::try_from(endpoint).map_err(|_| error(syscall::EINVAL))?,
            &request,
            &mut reply,
            &mut attached,
        )?;
        let after = execution_peer::capture_builtin(endpoint, b"org.mochios.logger")?;
        if before.image != after.image || message >> 32 != endpoint || message as u32 != 16 {
            return Err(error(syscall::EIO));
        }
        let status = u64::from_le_bytes(reply[..8].try_into().unwrap());
        if status != 0 {
            if attached.count != 0 {
                return Err(error(syscall::EIO));
            }
            return Err(error(status));
        }
        let length = usize::try_from(u64::from_le_bytes(reply[8..].try_into().unwrap()))
            .map_err(|_| error(syscall::EIO))?;
        let object = attached.handles[0];
        if attached.count != 1
            || !attached.is_user_delivery()
            || object.handle == 0
            || object.rights != handle::HANDLE_RIGHT_READ
            || object.reserved != 0
            || length == 0
            || length > MAX_SNAPSHOT
        {
            return Err(error(syscall::EIO));
        }
        let mut bytes = vec![0; length];
        let mut offset = 0;
        while offset < length {
            let end = length.min(offset + 4096);
            let count = handle::read_at(object.handle, &mut bytes[offset..end], offset as u64)?;
            if count == 0 || count > end - offset {
                return Err(error(syscall::EIO));
            }
            offset += count;
        }
        Ok(bytes)
    })();
    for object in attached.handles {
        if object.handle != 0 {
            let _ = handle::close(object.handle);
        }
    }
    result
}
