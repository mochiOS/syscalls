//! FD lookup and native-reference lifetime are one operation under STATE.
//! A close removes the FD immediately; its native reference remains usable by
//! already-started operations until their last guard is dropped.
use super::*;
use mochios_posix_client::handle_borrow::{Book, Pin};

// Native label capacity, not a POSIX descriptor quota. Retired descriptors may
// outnumber MAX_FDS when other threads repeatedly close and reuse one FD slot.
pub(super) static BORROWS: RuntimeMutex<Book<{ mnu_abi::PROCESS_MAX_OBJECT_HANDLES }>> =
    RuntimeMutex::new(Book::new());

pub(super) struct Lease {
    entry: FdEntry,
    pin: Option<Pin>,
}

impl Lease {
    pub(super) fn new(entry: FdEntry) -> Result<Self, c_int> {
        let pin = if entry.handle.close_owned {
            Some(BORROWS.lock().pin(entry.handle.lower_handle).ok_or(EBADF)?)
        } else {
            None
        };
        Ok(Self { entry, pin })
    }
}

impl core::ops::Deref for Lease {
    type Target = FdEntry;

    fn deref(&self) -> &FdEntry {
        &self.entry
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(pin) = self.pin.take() {
            let close = BORROWS.lock().release(pin);
            if close {
                close_object_handle(self.entry.handle.lower_handle as u32);
            }
        }
    }
}

pub(super) fn retire(object: FdObject) -> Result<(), c_int> {
    if object.close_owned {
        let close = BORROWS.lock().retire(object.lower_handle).ok_or(EBADF)?;
        if close {
            syscall_errno(syscall::raw_syscall1(
                syscall::SyscallNumber::HandleClose,
                object.lower_handle,
            ))?;
        }
    }
    Ok(())
}
