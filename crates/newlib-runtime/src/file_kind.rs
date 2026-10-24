//! Cache data-path classification once, while the open reply is still owned
//! by its cancellation scope. A terminal file retains filesystem metadata.
use super::*;

pub(super) fn opened(object: ObjectHandleAttachment<u32>, mode: u32) -> Result<FdKind, c_int> {
    match mode & 0o170000 {
        0o040000 => Ok(FdKind::ObjectDirectory),
        0o100000 => Ok(FdKind::ObjectFile),
        0o010000 => {
            let direction =
                object.rights & (syscall::HANDLE_RIGHT_READ | syscall::HANDLE_RIGHT_WRITE);
            if direction == syscall::HANDLE_RIGHT_READ || direction == syscall::HANDLE_RIGHT_WRITE {
                Ok(FdKind::ObjectFifo)
            } else {
                Err(EIO)
            }
        }
        0o020000 => {
            let entry = object_entry(
                u64::from(object.handle),
                object.rights,
                FdKind::ObjectSpecial,
                0,
            );
            match terminal_attributes(entry) {
                Ok(_) => Ok(FdKind::ObjectTerminalFile),
                Err(ENOTTY) => Ok(FdKind::ObjectSpecial),
                Err(error) => Err(error),
            }
        }
        _ => Ok(FdKind::ObjectSpecial),
    }
}
