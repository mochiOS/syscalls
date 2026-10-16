//! Keep an admitted file description alive across VM policy callbacks.
use super::*;

pub(super) fn with_source<T: Copy>(
    anonymous: bool,
    fd: c_int,
    operation: impl FnOnce(Option<FdEntry>) -> Result<T, c_int>,
) -> Result<T, c_int> {
    if anonymous {
        // Anonymous mappings neither validate nor borrow the supplied FD.
        return operation(None);
    }
    io_resources::with(|| with_fd_entry(fd), |source| operation(Some(**source)))
}
