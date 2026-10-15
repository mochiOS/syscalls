//! Path metadata retains directory authority until the reply is consumed.
use super::*;

struct Resources<'a> {
    _directory: Option<fd_lease::Lease>,
    _callbacks: mochios_posix_client::upcall_guard::Guard<'a>,
}

pub(super) fn at(dirfd: c_int, path: *const c_char, flags: u64) -> Result<NewlibStat, c_int> {
    let flags = match flags {
        0 => 0,
        AT_SYMLINK_NOFOLLOW => STAT_NOFOLLOW,
        _ => return Err(EINVAL),
    };
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let native = defer_native_delivery();
    let path = core::str::from_utf8(unsafe { c_bytes(path) }).map_err(|_| EINVAL)?;
    if path.is_empty() {
        return Err(ENOENT);
    }
    if path.len() > posix_protocol::MAX_PATH_LEN {
        return Err(ENAMETOOLONG);
    }
    let (base, directory) = rename_posix_base(dirfd, path)?;
    let resources = Resources {
        _directory: directory,
        _callbacks: control
            .callback_resources
            .defer_callbacks()
            .ok_or(EOVERFLOW)?,
    };
    let mut scope = core::pin::pin!(callback_resources::Scope::new(
        &control.callback_resources,
        control.active_signal_scope_id.load(Ordering::Acquire),
        resources
    ));
    // No application callback may abandon a lease before its owner is pinned.
    unsafe { scope.as_mut().activate() };
    drop(native);
    let result = (|| {
        let client = posix_client().map_err(map_posix_client_error)?;
        let status = client
            .stat_at(base, flags, path)
            .map_err(map_posix_client_error)?;
        translate_posix_stat(&status)
    })();
    {
        let _native = defer_native_delivery();
        unsafe { scope.as_mut().retire() };
    }
    // No borrowed Handle or response owner remains when C can escape.
    drain_pending_signals()?;
    result
}
