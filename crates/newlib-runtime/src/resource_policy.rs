//! Process-local read-only resource policy. Only initial discovery uses IPC.
use super::*;
use posix_protocol::resource_policy::{Error, READER_RIGHTS, ResourcePolicy};

static POLICY: RuntimeMutex<Option<Mapping>> = RuntimeMutex::new(None);

pub(super) struct Mapping(u64);

impl Mapping {
    fn open() -> Result<Self, c_int> {
        let client = posix_client().map_err(map_posix_client_error)?;
        // This page cannot supply its own admission limit before it is
        // mapped. One allocation-free scalar RPC bootstraps that limit;
        // subsequent reads, including ordinary map admission, use the page.
        let limit = client
            .resource_limit(0, posix_protocol::RLIMIT_AS, None)
            .map_err(map_posix_client_error)?;
        let handle = client
            .resource_policy_handle()
            .map_err(map_posix_client_error)?
            .handle;
        let result = (|| {
            // Check actual native authority/type/extent, not just the reply's
            // advertised rights. The service publishes one fixed RAM page.
            if syscall_errno(syscall::raw_syscall1(
                syscall::SyscallNumber::HandleRightsGet,
                u64::from(handle),
            ))? != READER_RIGHTS
            {
                return Err(EACCES);
            }
            if syscall_errno(syscall::raw_syscall1(
                syscall::SyscallNumber::MemoryObjectLength,
                u64::from(handle),
            ))? != PAGE_SIZE as u64
            {
                return Err(EIO);
            }
            let address = address_space::Limit::from_soft(limit.soft).map(
                0,
                PAGE_SIZE as u64,
                mnu_abi::MEMORY_ACCESS_READ,
                mnu_abi::MEMORY_MAP_SHARED,
                u64::from(handle),
                0,
            )?;
            let mapping = Self(address);
            if address == 0 || address % PAGE_SIZE as u64 != 0 {
                return Err(EIO);
            }
            mapping.policy().validate().map_err(policy_error)?;
            Ok(mapping)
        })();
        // Mapping retains the RAM object independently. Never retain this
        // non-transferable temporary reference across a Handle-table capture.
        close_object_handle(handle);
        result
    }

    fn policy(&self) -> &ResourcePolicy {
        // Safety: native RAM has the checked extent and page alignment. The
        // service initialized the atomic layout before delegation. No reference
        // escapes this mapping's lifetime or the callback-deferring POLICY lock.
        // ResourcePolicy::read uses only read-only-safe Relaxed atomic loads.
        unsafe { &*(self.0 as *const ResourcePolicy) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        let _ = syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryUnmap,
            self.0,
            PAGE_SIZE as u64,
        );
    }
}

fn policy_error(error: Error) -> c_int {
    match error {
        Error::InvalidResource => EINVAL,
        Error::Busy => EAGAIN,
        Error::UnsupportedTarget => ENOTSUP,
        _ => EIO,
    }
}

pub(super) fn read(resource: u32) -> Result<posix_protocol::ResourceLimit, c_int> {
    if resource >= posix_protocol::RLIMIT_COUNT {
        return Err(EINVAL);
    }
    loop {
        let result = {
            let mut guard = POLICY.lock();
            if guard.is_none() {
                *guard = Some(Mapping::open()?);
            }
            guard.as_ref().unwrap().policy().read(resource)
        };
        match result {
            // A bounded attempt holds the lock only while borrowing the page.
            // Retry outside it; never report stale or unlimited policy.
            Err(Error::Busy) => {
                syscall_errno(syscall::raw_syscall0(syscall::SyscallNumber::ThreadYield))?;
            }
            other => return other.map_err(policy_error),
        }
    }
}

/// Acquire after allocator and before STATE. SyscallEndpointTransport and
/// Client's control messages use fixed stack buffers; discovery must never
/// allocate through libc. This excludes transient Handles and incomplete
/// initialization from fork without deadlocking allocator-side policy reads.
pub(super) fn freeze_for_clone() -> RuntimeMutexGuard<'static, Option<Mapping>> {
    POLICY.lock()
}

/// Called with the copied freeze guard, before any child policy access.
/// The child is already registered by its parent before native resume, so
/// its next read can lazily discover its own independently published page.
pub(super) fn reset_child(guard: &mut RuntimeMutexGuard<'_, Option<Mapping>>) {
    drop(guard.take());
}
