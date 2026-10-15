//! Contiguous newlib break arena. POSIX policy stays outside the native VM ABI.
use super::{EINVAL, ENOMEM, NATIVE_READ_WRITE, address_space, align_up, syscall, syscall_errno};

#[derive(Clone, Copy)]
#[repr(C)]
pub(super) struct HeapState {
    pub(super) initialized: bool,
    pub(super) base: usize,
    pub(super) current_break: usize,
    pub(super) mapped_end: usize,
    /// Actual VM reservation, not a claim on an already returned tail.
    pub(super) reserved_end: usize,
    /// A failed rollback must retain ownership until a later unmap succeeds.
    pub(super) pending_release: Option<(usize, usize)>,
    /// Launch-time address ceiling, not a fixed allocator-size limit.
    pub(super) maximum_end: usize,
    pub(super) page_size: usize,
}

impl HeapState {
    /// Return unused virtual space, not merely resident frames. The native
    /// anonymous unmap transaction either succeeds or leaves the range intact.
    /// Keep the placement window: later growth must reserve exact free pages,
    /// never assume that an unmapped tail still belongs to this allocator.
    pub(super) fn trim_unused(&mut self) -> Result<(), i32> {
        if let Some((address, length)) = self.pending_release {
            syscall_errno(syscall::raw_syscall2(
                syscall::SyscallNumber::MemoryUnmap,
                address as u64,
                length as u64,
            ))?;
            self.pending_release = None;
        }
        if !self.initialized || self.base == 0 {
            return Ok(());
        }
        let end = align_up(self.current_break, self.page_size).ok_or(ENOMEM)?;
        if end < self.base || end > self.reserved_end {
            return Err(ENOMEM);
        }
        if end < self.reserved_end {
            syscall_errno(syscall::raw_syscall2(
                syscall::SyscallNumber::MemoryUnmap,
                end as u64,
                (self.reserved_end - end) as u64,
            ))?;
            self.reserved_end = end;
            self.mapped_end = self.mapped_end.min(end);
        }
        Ok(())
    }

    pub(super) fn adjust(
        &mut self,
        increment: isize,
        image_data_bytes: usize,
        data_limit: u64,
        memory_limit: address_space::Limit,
    ) -> Result<usize, i32> {
        if !self.initialized {
            return Err(ENOMEM);
        }
        if self.pending_release.is_some() {
            self.trim_unused()?;
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

        // Reclamation is independently committed even if later growth fails.
        // It never changes the logical break or any bytes still in use.
        if memory_limit.is_finite() {
            self.trim_unused()?;
        }
        let previous = *self;
        // Publish growth only after activation succeeds. Failed growth must
        // release newly acquired pages but retain the previous live prefix.
        let mut next = *self;
        let mut reservation = None;
        let result = (|| {
            if next.base == 0 {
                // Prefer an initial placement span before independent stacks
                // are created. Returned space is free: growth must reacquire
                // exact pages. This preference is not a maximum break size.
                const PREFERRED_RESERVATION_BYTES: usize = 256 * 1024 * 1024;
                let minimum = align_up(desired.max(1), next.page_size).ok_or(ENOMEM)?;
                let mut length = PREFERRED_RESERVATION_BYTES.max(minimum);
                let mapped = loop {
                    match memory_limit.map(0, length as u64, 0, 0, 0, 0) {
                        Ok(mapped) => break mapped as usize,
                        Err(ENOMEM) if memory_limit.is_finite() && length > minimum => {
                            length = (length / 2 & !(next.page_size - 1)).max(minimum);
                        }
                        Err(error) => return Err(error),
                    }
                };
                reservation = Some((mapped, length));
                let end = mapped.checked_add(length).ok_or(ENOMEM)?;
                if mapped == 0 || end > next.maximum_end {
                    return Err(ENOMEM);
                }
                next.base = mapped;
                next.current_break = mapped;
                next.mapped_end = mapped;
                next.reserved_end = end;
            }
            let old_break = next.current_break;
            let new_break = next.base.checked_add(desired).ok_or(ENOMEM)?;
            if new_break > next.maximum_end {
                return Err(ENOMEM);
            }
            let target_end = align_up(new_break, next.page_size).ok_or(ENOMEM)?;
            if target_end > next.maximum_end {
                return Err(ENOMEM);
            }
            if previous.base == 0 && memory_limit.is_finite() && target_end < next.reserved_end {
                // The initial placement reservation has advanced the native
                // cursor past the chosen window. Do not charge its unused
                // tail to a small AS budget, even before the first malloc.
                syscall_errno(syscall::raw_syscall2(
                    syscall::SyscallNumber::MemoryUnmap,
                    target_end as u64,
                    (next.reserved_end - target_end) as u64,
                ))?;
                next.reserved_end = target_end;
                reservation =
                    (target_end > next.base).then_some((next.base, target_end - next.base));
            }
            if target_end > next.reserved_end {
                let length = target_end - next.reserved_end;
                let mapped = memory_limit
                    .map(
                        next.reserved_end as u64,
                        length as u64,
                        0,
                        mnu_abi::MEMORY_MAP_EXACT,
                        0,
                        0,
                    )
                    .map_err(|error| if error == EINVAL { ENOMEM } else { error })?
                    as usize;
                reservation = Some((mapped, length));
                if mapped != next.reserved_end {
                    return Err(ENOMEM);
                }
                next.reserved_end = target_end;
            }
            if new_break > next.mapped_end {
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
                    let restore_end = target_end.min(previous.reserved_end);
                    if previous.base != 0 && restore_end > previous.mapped_end {
                        syscall_errno(syscall::raw_syscall3(
                            syscall::SyscallNumber::MemoryProtect,
                            previous.mapped_end as u64,
                            (restore_end - previous.mapped_end) as u64,
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
                    if let Err(cleanup_error) = syscall_errno(syscall::raw_syscall2(
                        syscall::SyscallNumber::MemoryUnmap,
                        address as u64,
                        length as u64,
                    )) {
                        self.pending_release = Some((address, length));
                        return Err(cleanup_error);
                    }
                }
                Err(error)
            }
        }
    }
}
