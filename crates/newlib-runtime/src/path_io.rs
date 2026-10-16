//! Capture a pathname before callbacks and retain its directory authority
//! through service calls and caller-memory copies, including nonlocal exits.
use super::*;

struct Resources {
    path: [u8; posix_protocol::MAX_PATH_LEN],
    length: usize,
    base: StatAtBase<u32>,
    directory: Option<fd_lease::Lease>,
}

impl Resources {
    fn empty() -> Self {
        Self {
            path: [0; posix_protocol::MAX_PATH_LEN],
            length: 0,
            base: StatAtBase::ProcessCwd,
            directory: None,
        }
    }

    fn capture(&mut self, dirfd: c_int, path: *const c_char) -> Result<(), c_int> {
        let resources = self;
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
        let path = &resources.path[..length];
        let (base, directory) = rename_posix_base(dirfd, path)?;
        resources.directory = directory;
        resources.base = base;
        Ok(())
    }

    fn bytes(&self) -> &[u8] {
        &self.path[..self.length]
    }
}

pub(super) fn at<T: Copy>(
    dirfd: c_int,
    path: *const c_char,
    operation: impl FnOnce(StatAtBase<u32>, &[u8]) -> Result<T, c_int>,
) -> Result<T, c_int> {
    io_resources::with_initialized(
        || Ok(Resources::empty()),
        |resources| resources.capture(dirfd, path),
        |resources| operation(resources.base, resources.bytes()),
    )
}

pub(super) fn pair<T: Copy>(
    old_dirfd: c_int,
    old_path: *const c_char,
    new_dirfd: c_int,
    new_path: *const c_char,
    operation: impl FnOnce(StatAtBase<u32>, &[u8], StatAtBase<u32>, &[u8]) -> Result<T, c_int>,
) -> Result<T, c_int> {
    io_resources::with_initialized(
        || Ok([Resources::empty(), Resources::empty()]),
        |resources| {
            // Both owners are registered before the first input read. A fault
            // in the second pathname must also retire the first directory.
            resources[0].capture(old_dirfd, old_path)?;
            resources[1].capture(new_dirfd, new_path)
        },
        |resources| {
            operation(
                resources[0].base,
                resources[0].bytes(),
                resources[1].base,
                resources[1].bytes(),
            )
        },
    )
}

pub(super) fn rename(
    old_dirfd: c_int,
    old_path: *const c_char,
    new_dirfd: c_int,
    new_path: *const c_char,
) -> Result<(), c_int> {
    pair(
        old_dirfd,
        old_path,
        new_dirfd,
        new_path,
        |old_base, old_path, new_base, new_path| {
            posix_client()
                .map_err(map_posix_client_error)?
                .rename_at(old_base, old_path, new_base, new_path)
                .map_err(map_posix_client_error)
        },
    )
}

// Public newlib ABI, not the Linux syscall ABI or the IPC wire flags.
pub(super) const AT_SYMLINK_FOLLOW: c_int = 0x0004;

pub(super) fn link(
    old_dirfd: c_int,
    old_path: *const c_char,
    new_dirfd: c_int,
    new_path: *const c_char,
    flags: c_int,
) -> Result<(), c_int> {
    if flags & !AT_SYMLINK_FOLLOW != 0 {
        return Err(EINVAL);
    }
    let flags = if flags & AT_SYMLINK_FOLLOW != 0 {
        posix_protocol::LINK_FOLLOW_SOURCE
    } else {
        0
    };
    pair(
        old_dirfd,
        old_path,
        new_dirfd,
        new_path,
        |old_base, old_path, new_base, new_path| {
            posix_client()
                .map_err(map_posix_client_error)?
                .link_at(old_base, old_path, new_base, new_path, flags)
                .map_err(map_posix_client_error)
        },
    )
}

pub(super) fn symlink(
    target: *const c_char,
    dirfd: c_int,
    path: *const c_char,
) -> Result<(), c_int> {
    // The target is literal text: the synthetic cwd base never borrows a FD
    // or resolves it. Only the link's parent supplies directory authority.
    pair(-2, target, dirfd, path, |_, target, base, path| {
        posix_client()
            .map_err(map_posix_client_error)?
            .symlink_at(target, base, path)
            .map_err(map_posix_client_error)
    })
}

pub(super) fn access(
    dirfd: c_int,
    path: *const c_char,
    mode: c_int,
    flags: c_int,
) -> Result<(), c_int> {
    const AT_EACCESS: c_int = 1;
    const AT_NOFOLLOW: c_int = 2;
    if mode & !7 != 0 || flags & !(AT_EACCESS | AT_NOFOLLOW) != 0 {
        return Err(EINVAL);
    }
    let options = if flags & AT_EACCESS != 0 {
        posix_protocol::ACCESS_EFFECTIVE_IDS
    } else {
        0
    } | if flags & AT_NOFOLLOW != 0 {
        posix_protocol::ACCESS_NOFOLLOW
    } else {
        0
    };
    at(dirfd, path, |base, path| {
        let base = match base {
            StatAtBase::ProcessRoot => AccessAtBase::ProcessRoot,
            StatAtBase::ProcessCwd => AccessAtBase::ProcessCwd,
            StatAtBase::Directory(handle) => AccessAtBase::Directory(handle),
        };
        posix_client()
            .map_err(map_posix_client_error)?
            .access_at(base, options, mode as u32, path)
            .map_err(map_posix_client_error)
    })
}

pub(super) fn chmod(dirfd: c_int, path: *const c_char, mode: u32) -> Result<(), c_int> {
    at(dirfd, path, |base, path| {
        posix_client()
            .map_err(map_posix_client_error)?
            .chmod_at(base, path, mode)
            .map_err(map_posix_client_error)
    })
}

pub(super) fn chdir(path: *const c_char) -> Result<(), c_int> {
    at(-2, path, |base, path| {
        posix_client()
            .map_err(map_posix_client_error)?
            .chdir_at(base, path)
            .map_err(map_posix_client_error)
    })
}

pub(super) fn chroot(path: *const c_char) -> Result<(), c_int> {
    at(-2, path, |base, path| {
        posix_client()
            .map_err(map_posix_client_error)?
            .chroot_at(base, path)
            .map_err(map_posix_client_error)
    })
}

pub(super) fn fchdir(fd: c_int) -> Result<(), c_int> {
    io_resources::with(
        || with_fd_entry(fd),
        |entry| change_directory_entry(**entry),
    )
}

pub(super) fn chown(
    dirfd: c_int,
    path: *const c_char,
    uid: u32,
    gid: u32,
    flags: u32,
) -> Result<(), c_int> {
    at(dirfd, path, |base, path| {
        posix_client()
            .map_err(map_posix_client_error)?
            .chown_at(base, path, uid, gid, flags)
            .map_err(map_posix_client_error)
    })
}

pub(super) fn unlink(dirfd: c_int, path: *const c_char, options: u32) -> Result<(), c_int> {
    at(dirfd, path, |base, path| {
        posix_client()
            .map_err(map_posix_client_error)?
            .unlink_at(base, options, path)
            .map_err(map_posix_client_error)
    })
}

pub(super) fn mkdir(dirfd: c_int, path: *const c_char, mode: u32) -> Result<(), c_int> {
    at(dirfd, path, |base, path| {
        let base = match base {
            StatAtBase::ProcessRoot => OpenAtBase::ProcessRoot,
            StatAtBase::ProcessCwd => OpenAtBase::ProcessCwd,
            StatAtBase::Directory(handle) => OpenAtBase::Directory(handle),
        };
        posix_client()
            .map_err(map_posix_client_error)?
            .mkdir_at(base, mode, path)
            .map_err(map_posix_client_error)
    })
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
