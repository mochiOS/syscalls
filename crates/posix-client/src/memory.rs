pub const PROT_NONE: i32 = 0;
pub const PROT_READ: i32 = 1 << 0;
pub const PROT_WRITE: i32 = 1 << 1;
pub const PROT_EXEC: i32 = 1 << 2;
pub const PROTECTION_ALL: i32 = PROT_READ | PROT_WRITE | PROT_EXEC;

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
