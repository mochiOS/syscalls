//! Thread stack ownership and protection; no POSIX policy enters the kernel.
use super::{EINVAL, NATIVE_READ_WRITE, PAGE_SIZE, address_space, c_int, syscall, syscall_errno};
use mochios_posix_client::thread_stack::Layout;

pub(super) fn allocate(stack_size: usize, guard_size: usize) -> Result<(usize, usize), c_int> {
    let layout = Layout::new(stack_size, guard_size, PAGE_SIZE).ok_or(EINVAL)?;
    // Reserve the guard and stack together. The AS admission limit includes
    // both, and another mapping cannot occupy the guard while the thread lives.
    let base = address_space::current()?.map(0, layout.mapping_size as u64, 0, 0, 0, 0)? as usize;
    let result = (|| {
        let usable = base.checked_add(layout.guard_size).ok_or(EINVAL)?;
        base.checked_add(layout.mapping_size).ok_or(EINVAL)?;
        syscall_errno(syscall::raw_syscall3(
            syscall::SyscallNumber::MemoryProtect,
            usable as u64,
            layout.usable_size as u64,
            NATIVE_READ_WRITE,
        ))?;
        Ok((base, layout.mapping_size))
    })();
    if result.is_err() {
        let _ = syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryUnmap,
            base as u64,
            layout.mapping_size as u64,
        );
    }
    result
}
