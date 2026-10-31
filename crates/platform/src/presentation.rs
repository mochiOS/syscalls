//! Transport for compositor-owned protected-presentation registrations.
use crate::{capability::presentation as w, handle, ipc, syscall};
fn invalid() -> syscall::SysError {
    syscall::SysError::from_raw(syscall::NativeError::InvalidFormat.into_raw() as i64)
}
struct Received {
    handles: ipc::IpcObjectHandles,
    borrowed: u32,
}
impl Drop for Received {
    fn drop(&mut self) {
        let entries =
            &self.handles.handles[..(self.handles.count as usize).min(self.handles.handles.len())];
        for (index, entry) in entries.iter().enumerate() {
            if entry.handle != 0
                && entry.handle != self.borrowed
                && !entries[..index]
                    .iter()
                    .any(|old| old.handle == entry.handle)
            {
                let _ = handle::close(entry.handle);
            }
        }
    }
}
pub fn command(
    destination: u32,
    command: w::Command,
    renderer: Option<ipc::IpcObjectHandle>,
) -> syscall::SysResult<w::Receipt> {
    if destination == 0 || matches!(command, w::Command::Register { .. }) != renderer.is_some() {
        return Err(invalid());
    }
    let mut received = Received {
        handles: Default::default(),
        borrowed: 0,
    };
    if let Some(renderer) = renderer {
        if renderer.handle == 0
            || renderer.reserved != 0
            || renderer.rights != handle::HANDLE_RIGHT_WAIT
        {
            return Err(invalid());
        }
        received.handles.count = 1;
        received.handles.handles[0] = renderer;
        received.borrowed = renderer.handle;
    }
    let request = w::encode_command(command).map_err(|_| invalid())?;
    let mut reply = [0; w::RECEIPT_BYTES];
    let message =
        ipc::call_object_handles(destination, &request, &mut reply, &mut received.handles)?;
    if message >> 32 != u64::from(destination)
        || message as u32 as usize != reply.len()
        || received.handles.count != 0
        || received.handles.delivery_flags != 0
    {
        return Err(invalid());
    }
    let receipt = w::decode_receipt(&reply).map_err(|_| invalid())?;
    if receipt.status != 0 {
        return Err(syscall::SysError::from_raw(-i64::from(receipt.status)));
    }
    let matches = match command {
        w::Command::Register { context, .. } => {
            receipt.context == context && receipt.stage == w::Stage::Pending
        }
        w::Command::Bind { surface, .. } => {
            receipt.surface == surface && receipt.stage == w::Stage::Pending
        }
        w::Command::Status { registration, .. } => receipt.registration == registration,
        w::Command::Cancel { registration, .. } => {
            receipt.registration == registration && receipt.stage == w::Stage::Revoked
        }
    };
    if !matches {
        return Err(invalid());
    }
    Ok(receipt)
}
pub fn session(destination: u32, context: w::Context) -> syscall::SysResult<()> {
    if destination == 0 {
        return Err(invalid());
    }
    let request = w::encode_session(context).map_err(|_| invalid())?;
    let mut reply = [0; 8];
    let mut received = Received {
        handles: Default::default(),
        borrowed: 0,
    };
    let message =
        ipc::call_object_handles(destination, &request, &mut reply, &mut received.handles)?;
    if message >> 32 != u64::from(destination)
        || message as u32 != 8
        || received.handles.count != 0
        || received.handles.delivery_flags != 0
    {
        return Err(invalid());
    }
    let status = u64::from_le_bytes(reply);
    if status > 4095 {
        return Err(invalid());
    }
    if status != 0 {
        return Err(syscall::SysError::from_raw(-(status as i64)));
    }
    Ok(())
}
