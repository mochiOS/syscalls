//! Snapshot the loader's AT_EXECFN through userspace path resolution before
//! constructors can change cwd/argv/environment. Names do not authenticate code.
use super::*;
#[path = "executable_name_snapshot.rs"]
mod snapshot;
static NAME: RuntimeMutex<snapshot::Name> = RuntimeMutex::new(snapshot::Name::empty());

pub(super) fn initialize(path: *const c_char) {
    if path.is_null() || !matches!(has_posix_environment(), Ok(true)) {
        return;
    }
    // Complete the path RPC before publishing into the process-local cache.
    let name = snapshot::Name::capture(|output| {
        path_io::at(-2, path, |base, path| {
            posix_client()
                .map_err(map_posix_client_error)?
                .canonical_path_at(base, path, output)
                .map_err(map_posix_client_error)
        })
    });
    *NAME.lock() = name;
}

#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub extern "C" fn getexecname() -> *const c_char {
    let name = NAME.lock();
    match name.value() {
        Ok(_) => name.bytes.as_ptr().cast(),
        Err(error) => {
            set_errno(error);
            ptr::null()
        }
    }
}
