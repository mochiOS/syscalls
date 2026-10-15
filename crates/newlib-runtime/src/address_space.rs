//! POSIX AS policy is read in user space; admission is a native VM operation.
use super::{
    c_int, has_posix_environment, map_kernel_errno, posix_protocol, resource_policy, syscall,
    syscall_errno,
};

#[derive(Clone, Copy)]
pub(super) struct Limit(u64);

impl Limit {
    pub(super) const UNLIMITED: Self = Self(posix_protocol::RLIM_INFINITY);
    pub(super) const fn is_finite(self) -> bool {
        self.0 != posix_protocol::RLIM_INFINITY
    }

    /// Also used to bootstrap the policy page from an authenticated RPC before
    /// that page can be mapped. Never read POLICY while holding STATE.
    pub(super) const fn from_soft(soft: u64) -> Self {
        Self(soft)
    }

    pub(super) fn map(
        self,
        address: u64,
        length: u64,
        access: u64,
        options: u64,
        backing_handle: u64,
        backing_offset: u64,
    ) -> Result<u64, c_int> {
        if self.0 == posix_protocol::RLIM_INFINITY {
            return syscall_errno(syscall::raw_syscall6(
                syscall::SyscallNumber::MemoryMap,
                address,
                length,
                access,
                options,
                backing_handle,
                backing_offset,
            ));
        }
        // Kernel counts all live mappings and checks/inserts under its VM
        // lock. No userspace byte counter or query-then-map race is involved.
        syscall::memory::map_bounded(syscall::memory::Request {
            address,
            length,
            access,
            options,
            backing_handle,
            backing_offset,
            byte_ceiling: self.0,
            reserved: 0,
        })
        .map_err(|error| map_kernel_errno(error.raw()))
    }
}

/// Read before STATE; heap growth performs its own reclamation under STATE.
pub(super) fn snapshot() -> Result<Limit, c_int> {
    if !has_posix_environment()? {
        // Native bootstrap processes have no POSIX policy. This does not
        // relax the Capability authority enforced by the native mapper.
        return Ok(Limit::UNLIMITED);
    }
    resource_policy::read(posix_protocol::RLIMIT_AS).map(|limit| Limit(limit.soft))
}

/// Non-heap mapping sites call this before taking any STATE-held table lock.
pub(super) fn current() -> Result<Limit, c_int> {
    let limit = snapshot()?;
    if limit.is_finite() {
        super::trim_heap_reservation()?;
    }
    Ok(limit)
}
