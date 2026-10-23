//! Serialize reference capture against publication/close of runtime-owned
//! Thread Handles. A numeric selector alone cannot pin its native object.
use super::*;

static REFERENCES: RuntimeMutex<()> = RuntimeMutex::new(());

pub(super) struct Reference {
    handle: u32,
    // No non-transferable temporary reference or copied mutex may enter a VM
    // snapshot. The activity also defers callbacks until this reference closes.
    _activity: thread_lifecycle::Mutation,
    // Native delivery deferral belongs to the creating runtime thread.
    _owner: core::marker::PhantomData<*mut ()>,
}

impl Reference {
    pub(super) fn handle(&self) -> u32 {
        self.handle
    }
}

impl Drop for Reference {
    fn drop(&mut self) {
        close_object_handle(self.handle);
    }
}

/// A source can be replaced or reclaimed only while holding this same lock.
/// Validate the generation again under the lock before duplicating; the TCB
/// may have been retired/reused since a caller last inspected its wait state.
pub(super) fn snapshot(thread: Pthread, rights: u64) -> Result<Reference, c_int> {
    let activity = thread_lifecycle::mutate();
    let references = REFERENCES.lock();
    let control = thread_control(thread).ok_or(ESRCH)?;
    let current = current_thread_control().is_some_and(|(current, _)| current == thread);
    let state = control.state.load(Ordering::Acquire);
    if state != THREAD_RUNNING && !(current && state == THREAD_STARTING) {
        return Err(ESRCH);
    }
    let source = control.native_handle.load(Ordering::Acquire);
    if source == 0 {
        return Err(ESRCH);
    }
    let raw = syscall_errno(syscall::raw_syscall2(
        syscall::SyscallNumber::HandleDuplicate,
        u64::from(source),
        rights,
    ))?;
    let handle = u32::try_from(raw).map_err(|_| EOVERFLOW)?;
    if handle == 0 {
        return Err(EIO);
    }
    drop(references);
    Ok(Reference {
        handle,
        _activity: activity,
        _owner: core::marker::PhantomData,
    })
}

/// Do not hold the reference lock across registration RPC or reclamation of
/// stacks/reent/allocator memory. Native Thread Handle close itself does no IPC.
pub(super) fn replace(control: &ThreadControl, handle: u32) {
    let _activity = thread_lifecycle::mutate();
    let _references = REFERENCES.lock();
    let previous = control.native_handle.swap(handle, Ordering::AcqRel);
    if previous != 0 {
        close_object_handle(previous);
    }
}

/// The caller owns the TCB's join/reap claim. Keep the source selector stable
/// only through a native status observation; never run application code here.
pub(super) fn with_control<T>(
    control: &ThreadControl,
    observe: impl FnOnce(u32) -> Result<T, c_int>,
) -> Result<T, c_int> {
    let _activity = thread_lifecycle::mutate();
    let _references = REFERENCES.lock();
    let handle = control.native_handle.load(Ordering::Acquire);
    if handle == 0 {
        return Err(ESRCH);
    }
    observe(handle)
}
