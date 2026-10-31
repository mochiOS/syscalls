//! Blocking reads on the private, blocking fork/exec status streams.
//! These are native references, never descriptors with caller-selected flags.
use super::*;

pub(super) fn exec_status(handle: u32) -> Result<mochios_posix_client::spawn::ExecStatus, c_int> {
    let mut packet = [0u8; mochios_posix_client::spawn::EXEC_ERROR_PACKET_LEN];
    let mut length = 0;
    loop {
        let count = read(handle, &mut packet[length..])?;
        length += count;
        match mochios_posix_client::spawn::decode_exec_status(&packet[..length], count == 0) {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(_) => return Err(EIO),
        }
    }
}

pub(super) fn read(handle: u32, output: &mut [u8]) -> Result<usize, c_int> {
    loop {
        let result = syscall::raw_syscall3(
            syscall::SyscallNumber::HandleRead,
            u64::from(handle),
            output.as_mut_ptr() as u64,
            output.len() as u64,
        );
        match result.into_result() {
            Ok(count) => {
                return usize::try_from(count)
                    .ok()
                    .filter(|count| *count <= output.len())
                    .ok_or(EIO);
            }
            Err(error) if error.native_error() == Some(syscall::NativeError::NotReady) => {
                // A pending native upcall wakes a blocking HandleRead with
                // NotReady. Dispatch userspace notifications and re-enter the
                // same blocking read; no new child or resource retry occurs.
                drain_pending_signals()?;
            }
            Err(error) => return Err(map_kernel_errno(error.raw())),
        }
    }
}
