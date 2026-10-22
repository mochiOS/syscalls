//! Do not release a created child until its PID has reached caller storage.
use super::*;

struct UnpublishedChild(Option<u32>);

impl Drop for UnpublishedChild {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            let _delivery = defer_native_delivery();
            // Registration succeeded before the exec-status stream closed.
            // Cleanup uses this owned ProcessHandle, never a PID lookup.
            cleanup_failed_child(u64::from(handle), true);
        }
    }
}

pub(super) fn publish(process_id: u64, handle: u32, output: *mut c_int) -> c_int {
    // The captured closure also owns rollback if scope registration fails.
    let child = UnpublishedChild(Some(handle));
    match io_resources::with(
        || Ok(child),
        |child| {
            let process_id = c_int::try_from(process_id).map_err(|_| EOVERFLOW)?;
            if process_id <= 0 {
                return Err(EIO);
            }
            // No callback or fallible provider operation follows publication.
            let _delivery = defer_native_delivery();
            let mut status = syscall::ProcessStatus::default();
            let result = syscall_errno(syscall::raw_syscall2(
                syscall::SyscallNumber::ProcessHandleStatus,
                u64::from(handle),
                (&mut status as *mut syscall::ProcessStatus) as u64,
            ))?;
            // EOF can also mean that the old image died before exec or could
            // not send its error packet. Only native committed-image metadata
            // proves replacement. A fast exit after a real exec is successful.
            if result != 0
                || status.process_id != process_id as u64
                || status.reserved != 0
                || !matches!(
                    status.state,
                    syscall::PROCESS_STATE_RUNNING | syscall::PROCESS_STATE_EXITED
                )
                || status.image_revision == 0
            {
                return Err(EIO);
            }
            user_copy::write(output.cast(), &process_id.to_ne_bytes())?;
            let handle = child.0.take().expect("unpublished child owner");
            close_object_handle(handle);
            Ok(0)
        },
    ) {
        Ok(value) => value,
        Err(error) => error,
    }
}
