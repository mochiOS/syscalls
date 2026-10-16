//! Newlib's C layout is an output format, not an IPC or kernel structure.
use super::*;

pub(super) fn write(destination: *mut c_void, status: &NewlibStat) -> Result<c_int, c_int> {
    // Never read a typed object's potentially uninitialized padding as bytes.
    // Populate a zeroed C-layout image field by field, preserving ABI offsets.
    let mut bytes = [0u8; core::mem::size_of::<NewlibStat>()];
    macro_rules! field {
        ($($field:ident).+) => {{
            let value = status.$($field).+.to_ne_bytes();
            let offset = core::mem::offset_of!(NewlibStat, $($field).+);
            bytes[offset..offset + value.len()].copy_from_slice(&value);
        }};
    }
    field!(st_dev);
    field!(st_ino);
    field!(st_mode);
    field!(st_nlink);
    field!(st_uid);
    field!(st_gid);
    field!(st_rdev);
    field!(st_size);
    field!(st_atim.tv_sec);
    field!(st_atim.tv_nsec);
    field!(st_mtim.tv_sec);
    field!(st_mtim.tv_nsec);
    field!(st_ctim.tv_sec);
    field!(st_ctim.tv_nsec);
    field!(st_blksize);
    field!(st_blocks);
    let offset = core::mem::offset_of!(NewlibStat, st_spare4);
    for (index, value) in status.st_spare4.iter().enumerate() {
        let value = value.to_ne_bytes();
        let start = offset + index * value.len();
        bytes[start..start + value.len()].copy_from_slice(&value);
    }
    user_copy::write(destination.cast(), &bytes)?;
    Ok(0)
}
