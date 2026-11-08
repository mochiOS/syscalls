//! BSD/Linux flock policy, independent of process-owned fcntl record locks.
//! Waiting owns a callback-tracked native reference; final close releases the
//! provider's description and lock even after dup, exec, fork or process exit.
use super::*;
use mochios_filesystem_protocol::whole_file_lock as wire;

/// Acquire, convert or release a whole-file advisory lock. LOCK_NB returns
/// EWOULDBLOCK on contention; blocking waits are interruptible and retain only
/// the exact open description. No pathname lookup or extra authority is used.
#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub extern "C" fn flock(fd: c_int, operation: c_int) -> c_int {
    let result = (|| {
        let mode = operation & !4; // LOCK_NB
        if !matches!(mode, 1 | 2 | 8) || operation & !15 != 0 {
            return Err(EINVAL);
        }
        let (_, control) = register_current_thread().ok_or(EAGAIN)?;
        let caught = control.nonrestart_signal_generation.load(Ordering::Acquire);
        // SAFETY: the resource contains only a tracked native reference. A
        // nonlocal callback exit cleans it; inherited private pins are invalid.
        unsafe {
            io_resources::with_fork_opaque(
                || with_fd_entry(fd),
                |_| true,
                |file| {
                    if file.handle.kind != FdKind::ObjectFile {
                        return Err(EBADF);
                    }
                    let bytes = (mode as u32).to_le_bytes();
                    loop {
                        if !file.is_current() {
                            return Err(EINTR);
                        }
                        let raw = {
                            let _delivery = defer_native_delivery();
                            if !file.is_current() {
                                return Err(EINTR);
                            }
                            syscall::raw_syscall6(
                                syscall::SyscallNumber::HandleControl,
                                file.handle.lower_handle,
                                wire::UPDATE,
                                bytes.as_ptr() as u64,
                                bytes.len() as u64,
                                0,
                                0,
                            )
                        };
                        if !file.is_current() {
                            return Err(EINTR);
                        }
                        match syscall_errno(raw) {
                            Ok(0) => return Ok(0),
                            Ok(_) => return Err(EIO),
                            Err(EAGAIN) if operation & 4 == 0 && mode != wire::UNLOCK as c_int => {}
                            Err(error) => return Err(error),
                        }
                        drain_pending_signals()?;
                        if control.nonrestart_signal_generation.load(Ordering::Acquire) != caught
                            || io_cancellation_requested(control)
                        {
                            return Err(EINTR);
                        }
                        // Bounded sleep, never a busy-spin or blocking provider
                        // RPC that could prevent the lock owner from releasing.
                        syscall_errno(syscall::raw_syscall1(syscall::SyscallNumber::Sleep, 2))?;
                    }
                },
            )
        }
    })();
    result_with_errno(result, -1)
}
