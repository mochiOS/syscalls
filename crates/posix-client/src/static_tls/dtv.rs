//! Private initial-module DTV. Only __tls_get_addr's index pair is ELF ABI;
//! this bounded table is userspace runtime data, never a kernel interface.
pub const TCB_BYTES: usize = 16;
pub const HEADER_BYTES: usize = 8;
pub const MODULE_BYTES: usize = 16;

pub fn address(
    mapping: &[u8],
    base: usize,
    thread_pointer: usize,
    module: usize,
    offset: usize,
) -> Option<usize> {
    base.checked_add(mapping.len())?;
    let word = |address: usize| {
        let start = address.checked_sub(base)?;
        Some(usize::from_le_bytes(
            mapping.get(start..start.checked_add(8)?)?.try_into().ok()?,
        ))
    };
    if word(thread_pointer)? != thread_pointer {
        return None;
    }
    let table = word(thread_pointer.checked_add(8)?)?;
    if table != thread_pointer.checked_add(TCB_BYTES)? {
        return None;
    }
    let count = word(table)?;
    let end = table
        .checked_add(HEADER_BYTES)?
        .checked_add(count.checked_mul(MODULE_BYTES)?)?;
    if end > base + mapping.len() || module == 0 || module > count {
        return None;
    }
    let entry = table + HEADER_BYTES + (module - 1) * MODULE_BYTES;
    let data = word(entry)?;
    let size = word(entry + 8)?;
    if data == 0 || data < base || data.checked_add(size)? > thread_pointer || offset > size {
        return None;
    }
    data.checked_add(offset)
}
