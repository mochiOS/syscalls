//! Contiguous newlib break arena. POSIX policy stays outside the native VM ABI.
use super::{EINVAL, ENOMEM, NATIVE_READ_WRITE, align_up, syscall, syscall_errno};

#[derive(Clone, Copy)]
#[repr(C)]
pub(super) struct HeapState {
    pub(super) initialized: bool,
    pub(super) base: usize,
    pub(super) current_break: usize,
    pub(super) mapped_end: usize,
    pub(super) maximum_end: usize,
    pub(super) page_size: usize,
}

impl HeapState {
    pub(super) fn adjust(
        &mut self,
        increment: isize,
        image_data_bytes: usize,
        data_limit: u64,
    ) -> Result<usize, i32> {
        if !self.initialized {
            return Err(ENOMEM);
        }
        let used = self.current_break.checked_sub(self.base).ok_or(ENOMEM)?;
        let desired = if increment >= 0 {
            used.checked_add(increment as usize).ok_or(ENOMEM)?
        } else {
            used.checked_sub(increment.unsigned_abs()).ok_or(EINVAL)?
        };
        // Check bytes, not rounded pages. Lowering a limit below existing use
        // must not prevent querying the break or releasing memory.
        if increment > 0 {
            let total = image_data_bytes.checked_add(desired).ok_or(ENOMEM)?;
            if total as u64 > data_limit {
                return Err(ENOMEM);
            }
        }

        // Commit metadata only after every fallible operation succeeds. An
        // unsuccessful first allocation must also release its reservation.
        let mut next = *self;
        let mut reservation = None;
        let result = (|| {
            if next.base == 0 {
                // Keep independent mappings (notably pthread stacks) outside
                // the contiguous arena required by newlib's allocator.
                const RESERVATION_BYTES: usize = 256 * 1024 * 1024;
                if desired > RESERVATION_BYTES {
                    return Err(ENOMEM);
                }
                let mapped = syscall_errno(syscall::raw_syscall6(
                    syscall::SyscallNumber::MemoryMap,
                    0,
                    RESERVATION_BYTES as u64,
                    0,
                    0,
                    0,
                    0,
                ))? as usize;
                reservation = Some((mapped, RESERVATION_BYTES));
                let end = mapped.checked_add(RESERVATION_BYTES).ok_or(ENOMEM)?;
                if mapped == 0 || end > next.maximum_end {
                    return Err(ENOMEM);
                }
                next.base = mapped;
                next.current_break = mapped;
                next.mapped_end = mapped;
                next.maximum_end = end;
            }
            let old_break = next.current_break;
            let new_break = next.base.checked_add(desired).ok_or(ENOMEM)?;
            if new_break > next.maximum_end {
                return Err(ENOMEM);
            }
            if new_break > next.mapped_end {
                let target_end = align_up(new_break, next.page_size).ok_or(ENOMEM)?;
                if target_end > next.maximum_end {
                    return Err(ENOMEM);
                }
                let length = target_end.checked_sub(next.mapped_end).ok_or(ENOMEM)?;
                let activation = syscall_errno(syscall::raw_syscall3(
                    syscall::SyscallNumber::MemoryProtect,
                    next.mapped_end as u64,
                    length as u64,
                    NATIVE_READ_WRITE,
                ));
                if let Err(error) = activation {
                    // MemoryProtect can edit a prefix before returning an
                    // error. Fresh arenas are unmapped below; for an existing
                    // arena restore only the formerly inaccessible extension.
                    if reservation.is_none() {
                        syscall_errno(syscall::raw_syscall3(
                            syscall::SyscallNumber::MemoryProtect,
                            next.mapped_end as u64,
                            length as u64,
                            0,
                        ))?;
                    }
                    return Err(error);
                }
                next.mapped_end = target_end;
            }
            next.current_break = new_break;
            Ok(old_break)
        })();
        match result {
            Ok(old_break) => {
                *self = next;
                Ok(old_break)
            }
            Err(error) => {
                if let Some((address, length)) = reservation {
                    let _ = syscall::raw_syscall2(
                        syscall::SyscallNumber::MemoryUnmap,
                        address as u64,
                        length as u64,
                    );
                }
                Err(error)
            }
        }
    }
}
