//! Checked byte snapshots of C vector metadata, shared by vector and socket I/O.
use super::*;

pub(super) fn read(source: *const IoVecMut, index: usize) -> Result<(*mut u8, usize), c_int> {
    let offset = index
        .checked_mul(core::mem::size_of::<IoVecMut>())
        .ok_or(EFAULT)?;
    let address = (source as usize).checked_add(offset).ok_or(EFAULT)?;
    let mut bytes = [0; core::mem::size_of::<IoVecMut>()];
    user_copy::read(address as *const u8, &mut bytes)?;
    let field = |offset| {
        usize::from_ne_bytes(
            bytes[offset..offset + core::mem::size_of::<usize>()]
                .try_into()
                .expect("C vector field fits its structure"),
        )
    };
    let base = field(core::mem::offset_of!(IoVecMut, iov_base));
    let length = field(core::mem::offset_of!(IoVecMut, iov_len));
    base.checked_add(length).ok_or(EFAULT)?;
    Ok((base as *mut u8, length))
}
