//! Synchronous compatibility policy over native deferred mapping refresh.
//! The receipt is tracked across returning or abandoning signal handlers;
//! native upcalls remain enabled while waiting for the worker.
use super::*;

struct Receipt(u32);

impl Drop for Receipt {
    fn drop(&mut self) {
        close_object_handle(self.0);
    }
}

pub(super) fn synchronize(address: u64, length: u64) -> Result<(), c_int> {
    io_resources::with(
        || {
            let raw = syscall::raw_syscall3(
                syscall::SyscallNumber::MemorySync,
                address,
                length,
                mnu_abi::MEMORY_SYNC_DEFERRED | mnu_abi::MEMORY_SYNC_REFRESH,
            )
            .into_result()
            .map_err(|error| mochios_posix_client::memory::sync_errno(error.raw()))?;
            let handle = u32::try_from(raw).map_err(|_| EIO)?;
            if handle == 0 {
                return Err(EIO);
            }
            Ok(Receipt(handle))
        },
        |receipt| wait(receipt.0),
    )
}

fn wait(handle: u32) -> Result<(), c_int> {
    use mnu_abi::completion;
    let (_, control) = current_thread_control().ok_or(EAGAIN)?;
    let caught = control.nonrestart_signal_generation.load(Ordering::Acquire);
    loop {
        drain_pending_signals()?;
        if control.nonrestart_signal_generation.load(Ordering::Acquire) != caught
            || io_cancellation_requested(control)
        {
            return Err(EINTR);
        }
        // Capture before reading readiness: a notification between this read
        // and the sleep must make the guarded wait retry, not get lost.
        let generation = control.multiplex_generation.load(Ordering::Acquire);
        let mut bytes = [0u8; completion::RECORD_LEN];
        let count = syscall_errno(syscall::raw_syscall4(
            syscall::SyscallNumber::HandleReadAt,
            u64::from(handle),
            bytes.as_mut_ptr() as u64,
            bytes.len() as u64,
            0,
        ))?;
        if count != bytes.len() as u64 {
            return Err(EIO);
        }
        let phase = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let error = u64::from_le_bytes(bytes[8..].try_into().unwrap());
        match phase {
            completion::SUCCEEDED if error == 0 => return Ok(()),
            completion::FAILED => {
                // A malformed FAILED(0) is not successful completion.
                return Err(if (error as i64) < 0 {
                    mochios_posix_client::memory::sync_errno(error as i64)
                } else {
                    EIO
                });
            }
            completion::PENDING if error == 0 => {}
            _ => return Err(EIO),
        }
        let mut item = syscall::HandleWaitItem {
            handle,
            interests: syscall::HANDLE_SIGNAL_READABLE,
            ..Default::default()
        };
        let guard = syscall::HandleWaitGuard {
            address: (&control.multiplex_generation as *const AtomicU64) as u64,
            expected: generation,
        };
        match syscall_errno(syscall::raw_syscall4(
            syscall::SyscallNumber::HandleWaitManyGuarded,
            (&mut item as *mut syscall::HandleWaitItem) as u64,
            1,
            syscall::HANDLE_WAIT_INFINITE,
            (&guard as *const syscall::HandleWaitGuard) as u64,
        )) {
            Err(EAGAIN) => continue,
            Err(error) => return Err(error),
            Ok(_) if item.observed & syscall::HANDLE_SIGNAL_READABLE != 0 => {}
            Ok(_) => return Err(EIO),
        }
    }
}
