pub const PROT_NONE: i32 = 0;
pub const PROT_READ: i32 = 1 << 0;
pub const PROT_WRITE: i32 = 1 << 1;
pub const PROT_EXEC: i32 = 1 << 2;
pub const PROTECTION_ALL: i32 = PROT_READ | PROT_WRITE | PROT_EXEC;

/// An unusable virtual address range is a POSIX mmap ENOMEM. The native
/// mapper reports an address failure, without choosing an API-specific errno.
pub const fn map_errno(status: i64) -> i32 {
    match mnu_abi::status::Error::from_raw(status as u64) {
        Some(mnu_abi::status::Error::InvalidAddress) => crate::newlib_errno::ENOMEM,
        _ => crate::newlib_errno::from_status(status),
    }
}

/// A missing range is a POSIX mprotect ENOMEM, not a faultable-copy EFAULT.
/// The native VM mechanism never chooses this operation-specific errno.
pub const fn protection_errno(status: i64) -> i32 {
    match mnu_abi::status::Error::from_raw(status as u64) {
        Some(mnu_abi::status::Error::InvalidAddress) => crate::newlib_errno::ENOMEM,
        _ => crate::newlib_errno::from_status(status),
    }
}

/// Unmap range and resource-ownership failures have operation-specific POSIX
/// meanings; native VM code must not choose these errno values.
pub const fn unmap_errno(status: i64) -> i32 {
    match mnu_abi::status::Error::from_raw(status as u64) {
        Some(mnu_abi::status::Error::InvalidAddress) => crate::newlib_errno::EINVAL,
        Some(mnu_abi::status::Error::AccessDenied) => crate::newlib_errno::EPERM,
        _ => crate::newlib_errno::from_status(status),
    }
}

/// POSIX msync reports an unmapped portion of the requested range as ENOMEM.
pub const fn sync_errno(status: i64) -> i32 {
    match mnu_abi::status::Error::from_raw(status as u64) {
        Some(mnu_abi::status::Error::InvalidAddress) => crate::newlib_errno::ENOMEM,
        _ => crate::newlib_errno::from_status(status),
    }
}

pub const MAP_SHARED: i32 = 0x01;
pub const MAP_PRIVATE: i32 = 0x02;
pub const MAP_FIXED: i32 = 0x10;
pub const MAP_ANONYMOUS: i32 = 0x20;
pub const MAP_NORESERVE: i32 = 0x4000;
pub const MAP_STACK: i32 = 0x20000;
pub const MAP_OPTIONS_ALL: i32 =
    MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS | MAP_NORESERVE | MAP_STACK;

pub const MS_ASYNC: i32 = 0x1;
pub const MS_INVALIDATE: i32 = 0x2;
pub const MS_SYNC: i32 = 0x4;

pub const POSIX_MADV_NORMAL: i32 = 0;
pub const POSIX_MADV_RANDOM: i32 = 1;
pub const POSIX_MADV_SEQUENTIAL: i32 = 2;
pub const POSIX_MADV_WILLNEED: i32 = 3;
pub const POSIX_MADV_DONTNEED: i32 = 4;

/// POSIX advice cannot change memory access semantics, even for DONTNEED.
/// The current VM keeps its allocation strategy and validates ownership
/// without touching contents, permissions or backing I/O. Optimization of
/// these optional hints can be added independently of the POSIX contract.
pub fn advise(
    address: u64,
    length: u64,
    advice: i32,
    page_size: u64,
    check_range: impl FnOnce(u64, u64) -> Result<(), i64>,
) -> Result<(), i32> {
    if !matches!(advice, POSIX_MADV_NORMAL..=POSIX_MADV_DONTNEED)
        || !page_size.is_power_of_two()
        || address & (page_size - 1) != 0
        || length == 0
    {
        return Err(crate::newlib_errno::EINVAL);
    }
    address
        .checked_add(length)
        .ok_or(crate::newlib_errno::ENOMEM)?;
    check_range(address, length).map_err(map_errno)
}

/// POSIX writeback policy, interpreted by the compatibility layer only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncPolicy {
    pub asynchronous: bool,
    pub invalidate: bool,
}

impl SyncPolicy {
    /// Refresh is always receipt-based, even when the POSIX caller waits.
    /// Compatibility flags themselves never cross the native syscall boundary.
    pub const fn native_options(self) -> u64 {
        let deferred = if self.asynchronous || self.invalidate {
            mnu_abi::MEMORY_SYNC_DEFERRED
        } else {
            0
        };
        deferred
            | if self.invalidate {
                mnu_abi::MEMORY_SYNC_REFRESH
            } else {
                0
            }
    }
}

pub const fn sync_policy(flags: i32) -> Option<SyncPolicy> {
    if flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0 {
        return None;
    }
    let mode = flags & (MS_ASYNC | MS_SYNC);
    if mode != MS_ASYNC && mode != MS_SYNC {
        return None;
    }
    Some(SyncPolicy {
        asynchronous: mode == MS_ASYNC,
        invalidate: flags & MS_INVALIDATE != 0,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeMap {
    pub options: u64,
    pub anonymous: bool,
}

/// Translates POSIX `PROT_*` policy into mnu's native VM access ABI.
///
/// Keeping this conversion in user space prevents POSIX flags from becoming
/// part of the kernel contract even when individual bit values happen to
/// match today.
pub const fn native_access(protection: i32) -> Option<u64> {
    if protection & !PROTECTION_ALL != 0 {
        return None;
    }
    let mut access = 0;
    if protection & PROT_READ != 0 {
        access |= mnu_abi::MEMORY_ACCESS_READ;
    }
    if protection & PROT_WRITE != 0 {
        access |= mnu_abi::MEMORY_ACCESS_WRITE;
    }
    if protection & PROT_EXEC != 0 {
        access |= mnu_abi::MEMORY_ACCESS_EXECUTE;
    }
    Some(access)
}

/// Translates POSIX mapping policy into the native placement/sharing ABI.
/// `MAP_STACK` and `MAP_NORESERVE` are accepted as user-space compatibility
/// hints and intentionally have no kernel representation.
pub const fn native_map(flags: i32) -> Option<NativeMap> {
    if flags & !MAP_OPTIONS_ALL != 0 {
        return None;
    }
    let sharing = flags & (MAP_SHARED | MAP_PRIVATE);
    if sharing != MAP_SHARED && sharing != MAP_PRIVATE {
        return None;
    }
    let mut options = 0;
    if flags & MAP_FIXED != 0 {
        options |= mnu_abi::MEMORY_MAP_EXACT | mnu_abi::MEMORY_MAP_REPLACE;
    }
    if sharing == MAP_SHARED {
        options |= mnu_abi::MEMORY_MAP_SHARED;
    }
    Some(NativeMap {
        options,
        anonymous: flags & MAP_ANONYMOUS != 0,
    })
}

/// Validate POSIX unmap alignment and normalize its byte length before entering
/// the native VM ABI. The kernel retains ownership and address-space checks.
pub const fn unmap_span(address: u64, length: u64) -> Option<u64> {
    if address & 4095 != 0 || length == 0 {
        return None;
    }
    let rounded = match length.checked_add(4095) {
        Some(length) => length & !4095,
        None => return None,
    };
    match address.checked_add(rounded) {
        Some(_) => Some(rounded),
        None => None,
    }
}
