//! POSIX volume accounting over one path resolution or a retained FD lease.
use super::*;
use mochios_filesystem_protocol::volume_status as wire;

#[repr(C)]
struct Statvfs {
    f_bsize: u64,
    f_frsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u32,
    f_ffree: u32,
    f_favail: u32,
    f_fsid: u64,
    f_flag: u64,
    f_namemax: u64,
}

fn write(output: *mut c_void, status: wire::Status) -> Result<c_int, c_int> {
    let files = u32::try_from(status.inodes).map_err(|_| EOVERFLOW)?;
    let free = u32::try_from(status.free_inodes).map_err(|_| EOVERFLOW)?;
    let value = Statvfs {
        f_bsize: u64::from(status.block_bytes),
        f_frsize: u64::from(status.block_bytes),
        f_blocks: status.blocks,
        f_bfree: status.free_blocks,
        // The current allocator has no privileged reserved-block policy.
        // Do not subtract a disk-format reservation that it does not enforce.
        f_bavail: status.free_blocks,
        f_files: files,
        f_ffree: free,
        f_favail: free,
        f_fsid: status.filesystem_id,
        f_flag: if status.flags & wire::READ_ONLY != 0 {
            1
        } else {
            0
        },
        f_namemax: u64::from(status.name_bytes_max),
    };
    let mut bytes = [0; core::mem::size_of::<Statvfs>()];
    macro_rules! field {
        ($field:ident) => {{
            let offset = core::mem::offset_of!(Statvfs, $field);
            let value = value.$field.to_ne_bytes();
            bytes[offset..offset + value.len()].copy_from_slice(&value);
        }};
    }
    field!(f_bsize);
    field!(f_frsize);
    field!(f_blocks);
    field!(f_bfree);
    field!(f_bavail);
    field!(f_files);
    field!(f_ffree);
    field!(f_favail);
    field!(f_fsid);
    field!(f_flag);
    field!(f_namemax);
    user_copy::write(output.cast(), &bytes)?;
    Ok(0)
}

fn query(entry: FdEntry) -> Result<wire::Status, c_int> {
    if matches!(
        entry.handle.kind,
        FdKind::ObjectFifo | FdKind::ObjectTerminalFile
    ) {
        return posix_client()
            .map_err(map_posix_client_error)?
            .volume_status(ObjectHandleAttachment {
                handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                rights: entry.rights,
            })
            .map_err(map_posix_client_error);
    }
    if !matches!(
        entry.handle.kind,
        FdKind::ObjectFile | FdKind::ObjectDirectory | FdKind::ObjectSpecial
    ) {
        return Err(ENOTSUP);
    }
    let mut bytes = [0; wire::RESPONSE_LEN];
    let count = syscall_errno(syscall::raw_syscall6(
        if entry.rights & syscall::HANDLE_RIGHT_READ != 0 {
            syscall::SyscallNumber::HandleQuery
        } else {
            syscall::SyscallNumber::HandleControl
        },
        entry.handle.lower_handle,
        wire::GET,
        0,
        0,
        bytes.as_mut_ptr() as u64,
        bytes.len() as u64,
    ))?;
    if count != bytes.len() as u64 {
        return Err(EIO);
    }
    wire::Status::decode(&bytes).ok_or(EIO)
}

#[unsafe(no_mangle)]
pub extern "C" fn fstatvfs(fd: c_int, output: *mut c_void) -> c_int {
    if output.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(
        io_resources::with(|| with_fd_entry(fd), |entry| write(output, query(**entry)?)),
        -1,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn statvfs(path: *const c_char, output: *mut c_void) -> c_int {
    if output.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = path_io::at(-2, path, |base, path| {
        let status = posix_client()
            .map_err(map_posix_client_error)?
            .volume_status_at(base, path)
            .map_err(map_posix_client_error)?;
        write(output, status)
    });
    result_with_errno(result, -1)
}
