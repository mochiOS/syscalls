use super::FilePanelMode;
use crate::syscall::{EINVAL, SysError};

/// Validate authority before adopting any received reference. The file for an
/// editing selection is read-only; only its separate target can replace it.
pub(super) fn panel_handles(
    mode: FilePanelMode,
    objects: &crate::ipc::IpcObjectHandles,
) -> Result<bool, SysError> {
    use crate::handle::*;
    let target = match (mode, objects.count) {
        (FilePanelMode::Open | FilePanelMode::Edit, 1) => false,
        (FilePanelMode::Edit | FilePanelMode::Save, 2) => true,
        _ => return Err(super::invalid()),
    };
    let file = objects.handles[0];
    let rights = HANDLE_RIGHT_READ
        | HANDLE_RIGHT_SEEK
        | HANDLE_RIGHT_DUPLICATE
        | HANDLE_RIGHT_TRANSFER
        | if mode == FilePanelMode::Save {
            HANDLE_RIGHT_WRITE
        } else {
            0
        };
    if !objects.is_user_delivery()
        || file.handle == 0
        || file.reserved != 0
        || file.rights != rights
    {
        return Err(super::invalid());
    }
    if target {
        let object = objects.handles[1];
        if object.handle == 0
            || object.reserved != 0
            || object.rights
                != HANDLE_RIGHT_CONTROL | HANDLE_RIGHT_DUPLICATE | HANDLE_RIGHT_TRANSFER
        {
            return Err(super::invalid());
        }
    }
    Ok(target)
}

/// Workspace failures carry negative statuses. Positive values are protocol
/// results (such as panel cancellation), never native error encodings.
pub(super) fn status_error(status: i32) -> SysError {
    SysError::from_raw(if status < 0 {
        i64::from(status)
    } else {
        EINVAL as i64
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        handle::*,
        ipc::{IpcObjectHandle, IpcObjectHandles},
    };
    fn selection() -> IpcObjectHandles {
        let mut objects = IpcObjectHandles::default();
        objects.count = 1;
        objects.handles[0] = IpcObjectHandle {
            handle: 1,
            reserved: 0,
            rights: HANDLE_RIGHT_READ
                | HANDLE_RIGHT_SEEK
                | HANDLE_RIGHT_DUPLICATE
                | HANDLE_RIGHT_TRANSFER,
        };
        objects
    }
    #[test]
    fn replies_cannot_expand_read_authority_or_smuggle_additional_objects() {
        let good = selection();
        assert_eq!(panel_handles(FilePanelMode::Open, &good).unwrap(), false);
        for rights in [
            good.handles[0].rights | HANDLE_RIGHT_WRITE,
            good.handles[0].rights | HANDLE_RIGHT_CONTROL,
            HANDLE_RIGHT_READ,
        ] {
            let mut bad = good;
            bad.handles[0].rights = rights;
            assert!(panel_handles(FilePanelMode::Open, &bad).is_err());
        }
        for count in [0, 2, 3, u32::MAX] {
            let mut bad = good;
            bad.count = count;
            assert!(panel_handles(FilePanelMode::Open, &bad).is_err());
        }
        let mut bad = good;
        bad.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
        assert!(panel_handles(FilePanelMode::Open, &bad).is_err());
        let mut bad = good;
        bad.handles[0].reserved = 1;
        assert!(panel_handles(FilePanelMode::Open, &bad).is_err());
    }
    #[test]
    fn save_requires_a_separate_exact_target_and_edit_never_receives_write_on_the_file() {
        let mut objects = selection();
        assert!(panel_handles(FilePanelMode::Save, &objects).is_err());
        objects.count = 2;
        objects.handles[1] = IpcObjectHandle {
            handle: 2,
            reserved: 0,
            rights: HANDLE_RIGHT_CONTROL | HANDLE_RIGHT_DUPLICATE | HANDLE_RIGHT_TRANSFER,
        };
        assert_eq!(panel_handles(FilePanelMode::Edit, &objects).unwrap(), true);
        objects.handles[0].rights |= HANDLE_RIGHT_WRITE;
        assert!(panel_handles(FilePanelMode::Edit, &objects).is_err());
        assert_eq!(panel_handles(FilePanelMode::Save, &objects).unwrap(), true);
        objects.handles[1].rights |= HANDLE_RIGHT_READ;
        assert!(panel_handles(FilePanelMode::Save, &objects).is_err());
    }
}
