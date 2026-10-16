//! Capture a pathname before callbacks and retain its directory authority
//! through service calls and caller-memory copies, including nonlocal exits.
use super::*;

struct Resources {
    path: [u8; posix_protocol::MAX_PATH_LEN],
    length: usize,
    base: StatAtBase<u32>,
    directory: Option<fd_lease::Lease>,
}

pub(super) fn at<T: Copy>(
    dirfd: c_int,
    path: *const c_char,
    operation: impl FnOnce(StatAtBase<u32>, &str) -> Result<T, c_int>,
) -> Result<T, c_int> {
    io_resources::with_initialized(
        || {
            Ok(Resources {
                path: [0; posix_protocol::MAX_PATH_LEN],
                length: 0,
                base: StatAtBase::ProcessCwd,
                directory: None,
            })
        },
        |resources| {
            if path.is_null() {
                return Err(EFAULT);
            }
            // Bound reads as well as the resulting wire pathname. No borrowed
            // caller string survives into a wait or application callback.
            let mut length = 0;
            loop {
                let byte = unsafe { path.cast::<u8>().add(length).read() };
                if byte == 0 {
                    break;
                }
                if length == resources.path.len() {
                    return Err(ENAMETOOLONG);
                }
                resources.path[length] = byte;
                length += 1;
            }
            if length == 0 {
                return Err(ENOENT);
            }
            resources.length = length;
            let path = core::str::from_utf8(&resources.path[..length]).map_err(|_| EINVAL)?;
            let (base, directory) = rename_posix_base(dirfd, path)?;
            resources.directory = directory;
            resources.base = base;
            Ok(())
        },
        |resources| {
            let path =
                core::str::from_utf8(&resources.path[..resources.length]).map_err(|_| EINVAL)?;
            operation(resources.base, path)
        },
    )
}

pub(super) fn readlink(
    dirfd: c_int,
    path: *const c_char,
    output: *mut c_char,
    size: usize,
) -> Result<isize, c_int> {
    if output.is_null() {
        return Err(EFAULT);
    }
    if size == 0 || size > isize::MAX as usize {
        return Err(EINVAL);
    }
    if (output as usize).checked_add(size).is_none() {
        return Err(EFAULT);
    }
    at(dirfd, path, |base, path| {
        let output = unsafe { core::slice::from_raw_parts_mut(output.cast::<u8>(), size) };
        let client = posix_client().map_err(map_posix_client_error)?;
        let read = client
            .readlink_at(base, path, output)
            .map_err(map_posix_client_error)?;
        isize::try_from(read).map_err(|_| EIO)
    })
}
