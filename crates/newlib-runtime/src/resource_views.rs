//! Process-local paths backed only by retained immutable directory authority.
//! A never-reused serial prevents a stale path from selecting a recycled label.
use super::resource_view_path::{ROOT_LEN, parse};
use super::*;
pub(super) const PATH_BYTES: usize = 128;
struct View {
    token: u64,
    epoch: u64,
    source: fd_lease::Lease,
}
pub(super) struct Registry {
    entries: [Option<View>; 64],
    next: u64,
}
impl Registry {
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; 64],
            next: 1,
        }
    }
}
pub(super) fn publish(handle: &mut u32, output: *mut c_char) -> Result<u64, c_int> {
    let epoch = FORK_EPOCH.load(Ordering::Acquire);
    let token = {
        let mut state = state();
        let views = &mut state.resource_views;
        for entry in &mut views.entries {
            if entry.as_ref().is_some_and(|v| v.epoch != epoch) {
                *entry = None;
            }
        }
        if views.entries.iter().all(Option::is_some) {
            return Err(EMFILE);
        }
        let token = views.next;
        views.next = token.checked_add(1).ok_or(EOVERFLOW)?;
        token
    };
    let mut path = [0; ROOT_LEN];
    super::resource_view_path::spell(token, &mut path)?;
    user_copy::write_c_string(output.cast(), &path)?;
    let rights = syscall::HANDLE_RIGHT_READ
        | syscall::HANDLE_RIGHT_SEEK
        | syscall::HANDLE_RIGHT_DUPLICATE
        | syscall::HANDLE_RIGHT_TRANSFER;
    let raw = core::mem::replace(handle, 0);
    let lease = fd_lease::Lease::adopt_private(object_entry(
        u64::from(raw),
        rights,
        FdKind::ObjectDirectory,
        O_CLOEXEC,
    ))?;
    // No callbacks, allocation or IPC between ownership transfer and publication.
    let mut state = state();
    let slot = state
        .resource_views
        .entries
        .iter_mut()
        .find(|slot| slot.is_none())
        .ok_or(EMFILE)?;
    *slot = Some(View {
        token,
        epoch,
        source: lease,
    });
    Ok(token)
}
pub(super) fn close(token: u64) -> Result<(), c_int> {
    let _delivery = defer_native_delivery();
    let view = {
        let mut state = state();
        let epoch = FORK_EPOCH.load(Ordering::Acquire);
        state
            .resource_views
            .entries
            .iter_mut()
            .find(|slot| {
                slot.as_ref()
                    .is_some_and(|v| v.token == token && v.epoch == epoch)
            })
            .ok_or(EBADF)?
            .take()
            .ok_or(EBADF)?
    };
    drop(view);
    Ok(())
}
/// Called only under a tracked I/O preparation with native delivery deferred.
pub(super) fn resolve(path: &[u8]) -> Result<Option<(usize, fd_lease::Lease)>, c_int> {
    let Some((token, skip)) = parse(path)? else {
        return Ok(None);
    };
    let state = state();
    let epoch = FORK_EPOCH.load(Ordering::Acquire);
    let view = state
        .resource_views
        .entries
        .iter()
        .flatten()
        .find(|v| v.token == token && v.epoch == epoch && v.source.is_current())
        .ok_or(ENOENT)?;
    let rights = view.source.rights;
    let raw = syscall_errno(syscall::raw_syscall2(
        syscall::SyscallNumber::HandleDuplicate,
        view.source.handle.lower_handle,
        rights,
    ))?;
    let raw = u32::try_from(raw).map_err(|_| EIO)?;
    let lease = fd_lease::Lease::adopt_private(object_entry(
        u64::from(raw),
        rights,
        FdKind::ObjectDirectory,
        O_CLOEXEC,
    ))?;
    Ok(Some((skip, lease)))
}
/// Reconstruct only the process-local spelling, after stat validates existence.
/// No physical installation path is exposed by canonicalization.
pub(super) fn canonical(path: *const c_char, output: &mut [u8]) -> Result<Option<usize>, c_int> {
    let mut captured = [0; posix_protocol::MAX_PATH_LEN];
    let len = user_copy::capture(path, &mut captured)?;
    let Some((_, _)) = parse(&captured[..len])? else {
        return Ok(None);
    };
    let mut nul = [0; posix_protocol::MAX_PATH_LEN + 1];
    nul[..len].copy_from_slice(&captured[..len]);
    path_io::at(-2, nul.as_ptr().cast(), |base, path| {
        posix_client()
            .map_err(map_posix_client_error)?
            .stat_at(base, 0, path)
            .map_err(map_posix_client_error)?;
        Ok(())
    })?;
    super::resource_view_path::canonical(&captured[..len], output).map(Some)
}
