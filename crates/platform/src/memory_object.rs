//! Owned native RAM objects and shared mappings. No descriptors, path lookup
//! or service-specific discovery are involved in this data path.

use crate::{handle, syscall};
use syscall::{SysError, SysResult, SyscallNumber};

const PAGE_BYTES: u64 = 4096;

pub struct MemoryObject {
    handle: handle::Handle,
}

impl MemoryObject {
    /// Create fixed, page-aligned RAM backing using the current native ABI.
    pub fn create(length: u64) -> SysResult<Self> {
        if length == 0 || length % PAGE_BYTES != 0 {
            return Err(SysError::from_raw(syscall::EINVAL as i64));
        }
        let raw = syscall::call2(SyscallNumber::MemoryObjectCreate, length, 0)?;
        let handle = u32::try_from(raw)
            .ok()
            .filter(|handle| *handle != 0)
            .ok_or(SysError::from_raw(syscall::EIO as i64))?;
        Ok(Self { handle })
    }

    /// Take ownership of an already-owned or IPC-received native object handle.
    /// Resource type and permissions remain enforced by the kernel on use.
    ///
    /// # Safety
    /// The caller must relinquish its ownership and ensure no other owner will
    /// close this handle. The number refers only to the current process table.
    pub unsafe fn from_owned_handle(handle: handle::Handle) -> Self {
        Self { handle }
    }

    /// Borrow the handle for an IPC attachment; this does not transfer ownership.
    pub fn handle(&self) -> handle::Handle {
        self.handle
    }

    pub fn length(&self) -> SysResult<u64> {
        syscall::call1(SyscallNumber::MemoryObjectLength, self.handle as u64)
    }

    pub fn rights(&self) -> SysResult<u64> {
        handle::rights(self.handle)
    }

    /// Close explicitly, returning ownership with the error if close fails.
    pub fn close(mut self) -> Result<(), (Self, SysError)> {
        match handle::close(self.handle) {
            Ok(()) => {
                self.handle = 0;
                Ok(())
            }
            Err(error) => Err((self, error)),
        }
    }

    /// Reserve a shared mapping. The kernel validates MAP/READ/WRITE rights;
    /// faults validate the live extent. Mapping ownership is independent of
    /// handle ownership, so a mapped view may outlive this object handle.
    pub fn map(&self, offset: u64, length: u64, access: u64) -> SysResult<MemoryMapping> {
        if offset % PAGE_BYTES != 0 || length == 0 || access & !syscall::MEMORY_ACCESS_ALL != 0 {
            return Err(SysError::from_raw(syscall::EINVAL as i64));
        }
        let capacity = length
            .checked_add(PAGE_BYTES - 1)
            .map(|length| length & !(PAGE_BYTES - 1))
            .filter(|capacity| offset.checked_add(*capacity).is_some())
            .ok_or(SysError::from_raw(syscall::EINVAL as i64))?;
        let address = syscall::call6(
            SyscallNumber::MemoryMap,
            0,
            capacity,
            access,
            syscall::MEMORY_MAP_SHARED,
            self.handle as u64,
            offset,
        )?;
        Ok(MemoryMapping { address, capacity })
    }
}

impl Drop for MemoryObject {
    fn drop(&mut self) {
        if self.handle != 0 {
            let _ = handle::close(self.handle);
        }
    }
}

pub struct MemoryMapping {
    address: u64,
    capacity: u64,
}

impl MemoryMapping {
    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Only raw pointers are exposed: attached peers may access backing
    /// concurrently, so Rust's exclusive/shared reference rules do not apply.
    pub fn as_ptr(&self) -> *const u8 {
        self.address as *const u8
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.address as *mut u8
    }

    /// Unmap explicitly. On failure the returned view still owns its mapping
    /// and can be retried; never discard it merely because revocation failed.
    pub fn unmap(mut self) -> Result<(), (Self, SysError)> {
        match syscall::call2(SyscallNumber::MemoryUnmap, self.address, self.capacity) {
            Ok(_) => {
                self.address = 0;
                Ok(())
            }
            Err(error) => Err((self, error)),
        }
    }
}

impl Drop for MemoryMapping {
    fn drop(&mut self) {
        // A failed unmap leaves the kernel region owning backing. Closing an
        // object handle never recycles pages still referenced by that region.
        if self.address != 0 {
            let _ = syscall::call2(SyscallNumber::MemoryUnmap, self.address, self.capacity);
        }
    }
}
