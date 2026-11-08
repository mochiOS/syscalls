//! Unix VM compatibility policy; the kernel receives only generic own-space
//! observation/discard operations, never MADV selectors or POSIX errno.
use super::*;

fn failed(raw: u64) -> bool {
    // Older kernels may reject a new mechanism using the legacy ENOSYS
    // range. Never mistake an unimplemented discard for successful advice.
    mnu_abi::status::is_error(raw) || (-4095..=-1).contains(&(raw as i64))
}

/// Snapshot one residency byte per touched page without faulting input pages
/// in. The result is transient; inaccessible retained RAM still counts.
///
/// # Safety
/// `vector` must hold ceil(length/PAGE_SIZE) writable bytes.
#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub unsafe extern "C" fn mincore(address: *mut c_void, length: usize, vector: *mut u8) -> c_int {
    let result = (|| {
        let start = address as usize;
        if start % PAGE_SIZE != 0 {
            return Err(EINVAL);
        }
        start.checked_add(length).ok_or(ENOMEM)?;
        if length == 0 {
            return Ok(0);
        }
        let pages = (length - 1) / PAGE_SIZE + 1;
        (vector as usize).checked_add(pages).ok_or(EFAULT)?;
        let checked = syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryRangeCheck,
            start as u64,
            length as u64,
        )
        .raw();
        if failed(checked) {
            return Err(mochios_posix_client::memory::map_errno(checked as i64));
        }
        if checked != 0 {
            return Err(EIO);
        }
        let mut offset = 0;
        while offset < pages {
            let count = (pages - offset).min(256);
            let mut bytes = [0u8; 256];
            let raw = syscall::raw_syscall4(
                syscall::SyscallNumber::MemoryResidencyRead,
                (start + offset * PAGE_SIZE) as u64,
                (count * PAGE_SIZE) as u64,
                bytes.as_mut_ptr() as u64,
                count as u64,
            )
            .raw();
            if failed(raw) {
                return Err(mochios_posix_client::memory::map_errno(raw as i64));
            }
            if raw != count as u64 {
                return Err(EIO);
            }
            user_copy::write((vector as usize + offset) as *mut u8, &bytes[..count])?;
            offset += count;
        }
        Ok(0)
    })();
    result_with_errno(result, -1)
}

/// Apply Unix memory advice to the caller's mappings. NORMAL/RANDOM/
/// SEQUENTIAL/WILLNEED are nonbinding hints; DONTNEED actually discards
/// private anonymous contents, preserving address and protection. File/shared
/// discard and unknown advice are unsupported, never simulated as success.
#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub extern "C" fn madvise(address: *mut c_void, length: usize, advice: c_int) -> c_int {
    let result = (|| {
        let start = address as usize;
        if start % PAGE_SIZE != 0 || !(0..=4).contains(&advice) {
            return Err(EINVAL);
        }
        let rounded = length.checked_add(PAGE_SIZE - 1).ok_or(ENOMEM)? & !(PAGE_SIZE - 1);
        start.checked_add(rounded).ok_or(ENOMEM)?;
        if rounded == 0 {
            return Ok(0);
        }
        let operation = if advice == 4 {
            syscall::SyscallNumber::MemoryDiscard
        } else {
            syscall::SyscallNumber::MemoryRangeCheck
        };
        let raw = syscall::raw_syscall2(operation, start as u64, rounded as u64).raw();
        if failed(raw) {
            return Err(mochios_posix_client::memory::map_errno(raw as i64));
        }
        if raw != 0 {
            return Err(EIO);
        }
        Ok(0)
    })();
    result_with_errno(result, -1)
}
