//! Fork-local ownership of a native Handle-table capture, not inherited by
//! the child. Its numeric ID is meaningful only in the parent's live table.
use super::*;

pub(super) struct Capture(Option<u32>);

impl Capture {
    pub(super) fn new() -> Result<Self, c_int> {
        let raw = syscall_errno(syscall::raw_syscall0(
            syscall::SyscallNumber::HandleTableCapture,
        ))?;
        let handle = u32::try_from(raw).map_err(|_| EOVERFLOW)?;
        if handle == 0 {
            return Err(EIO);
        }
        Ok(Self(Some(handle)))
    }

    pub(super) fn handle(&self) -> u32 {
        self.0.expect("parent-owned capture")
    }

    pub(super) fn records(&self, output: &mut [mnu_abi::HandleInfo]) -> Result<usize, c_int> {
        let mut bytes = [0u8; mnu_abi::handle_snapshot::HEADER_LEN
            + mnu_abi::process_create::MAX_HANDLES * mnu_abi::handle_snapshot::RECORD_LEN];
        let count = syscall_errno(syscall::raw_syscall4(
            syscall::SyscallNumber::HandleReadAt,
            u64::from(self.handle()),
            bytes.as_mut_ptr() as u64,
            bytes.len() as u64,
            0,
        ))?;
        let bytes = bytes
            .get(..usize::try_from(count).map_err(|_| EIO)?)
            .ok_or(EIO)?;
        mochios_posix_client::inheritance::decode_capture(bytes, output).map_err(
            |error| match error {
                mochios_posix_client::inheritance::Error::TooManyHandles
                | mochios_posix_client::inheritance::Error::BufferTooSmall => EAGAIN,
                _ => EIO,
            },
        )
    }

    /// Must precede *all* child Handle allocation and copied guard release.
    /// The parent's capture is not inherited; closing its copied number could
    /// otherwise close an unrelated reference allocated in that child slot.
    pub(super) fn disarm_child(&mut self) {
        self.0 = None;
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            close_object_handle(handle);
        }
    }
}
