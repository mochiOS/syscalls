//! FD lookup and native-reference lifetime are one operation under STATE.
//! A close removes the FD immediately; its native reference remains usable by
//! already-started operations until their last guard is dropped.
use super::*;
use mochios_posix_client::handle_borrow::{Book, Pin};

// Native label capacity, not a POSIX descriptor quota. Retired descriptors may
// outnumber MAX_FDS when other threads repeatedly close and reuse one FD slot.
pub(super) static BORROWS: RuntimeMutex<Book<{ mnu_abi::PROCESS_MAX_OBJECT_HANDLES }>> =
    RuntimeMutex::new(Book::new());

/// Launch keys are associations, not separately owned native references.
/// Different FD keys may therefore resolve to the very same native label.
pub(super) struct RestoreReferences {
    labels: [u64; MAX_FDS],
    count: usize,
}

impl RestoreReferences {
    pub(super) fn new() -> Self {
        Self {
            labels: [0; MAX_FDS],
            count: 0,
        }
    }

    pub(super) fn register(&mut self, object: FdObject) -> Result<(), c_int> {
        if !object.close_owned {
            return Ok(());
        }
        if object.lower_handle == 0
            || object.lower_handle > mnu_abi::PROCESS_MAX_OBJECT_HANDLES as u64
        {
            return Err(EBADF);
        }
        if self.labels[..self.count].contains(&object.lower_handle) {
            BORROWS.lock().retain(object.lower_handle).ok_or(EBADF)?;
        } else {
            let slot = self.labels.get_mut(self.count).ok_or(EBADF)?;
            *slot = object.lower_handle;
            self.count += 1;
        }
        Ok(())
    }
}

pub(super) struct Lease {
    entry: FdEntry,
    pin: Option<Pin>,
    // A private operation reference is never inherited. Its copied guard can
    // resume after fork inside a returning handler, but must not release a pin
    // or native label which child startup has discarded and possibly reused.
    private_epoch: Option<u64>,
    // Fork discard attributes the pin to the acquiring runtime thread. Do not
    // let an operation's destructor migrate to a different surviving thread.
    _thread: core::marker::PhantomData<*mut ()>,
}

impl Lease {
    /// A private reference copied across fork is invalid even if its old
    /// numeric slot is occupied again. Check before dispatch and after upcalls.
    pub(super) fn is_current(&self) -> bool {
        self.private_epoch
            .is_none_or(|epoch| epoch == FORK_EPOCH.load(Ordering::Acquire))
    }

    /// Own a fresh native reference without installing a POSIX descriptor.
    /// Preparation must defer native delivery until the lease is published
    /// in a callback resource scope, as for ordinary FD creation.
    pub(super) fn adopt_private(entry: FdEntry) -> Result<Self, c_int> {
        let pin = BORROWS
            .lock()
            .pin_private(entry.handle.lower_handle, newlib_lock_identity());
        match pin {
            Ok(pin) => Ok(Self {
                entry,
                pin: Some(pin),
                private_epoch: Some(FORK_EPOCH.load(Ordering::Acquire)),
                _thread: core::marker::PhantomData,
            }),
            Err(error) => {
                close_object_handle(entry.handle.lower_handle as u32);
                Err(match error {
                    mochios_posix_client::handle_borrow::PinError::Capacity => ENOMEM,
                    _ => EBADF,
                })
            }
        }
    }

    pub(super) fn new(entry: FdEntry) -> Result<Self, c_int> {
        let pin = if entry.handle.close_owned {
            Some(
                BORROWS
                    .lock()
                    .pin_owned(entry.handle.lower_handle, newlib_lock_identity())
                    .map_err(|error| match error {
                        mochios_posix_client::handle_borrow::PinError::Capacity => ENOMEM,
                        _ => EBADF,
                    })?,
            )
        } else {
            None
        };
        Ok(Self {
            entry,
            pin,
            private_epoch: None,
            _thread: core::marker::PhantomData,
        })
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
            if !self.is_current() {
                return;
            }
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
