//! Owned native RAM objects and shared mappings. No descriptors, path lookup
//! or service-specific discovery are involved in this data path.

use crate::{handle, syscall};
use syscall::{SysError, SysResult, SyscallNumber};

const PAGE_BYTES: u64 = 4096;
pub const READONLY_BUFFER_RIGHTS: u64 = syscall::HANDLE_RIGHT_READ | syscall::HANDLE_RIGHT_MAP;

/// Userspace buffer notification. The resource is attached to IPC. This view
/// describes offsets, not a sender pointer or a byte-range capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadOnlyOffer {
    pub offset: u64,
    pub length: u64,
}

impl ReadOnlyOffer {
    pub const MAGIC: [u8; 4] = *b"MRAM";
    pub const WIRE_LENGTH: usize = 32;

    pub fn encode(self) -> SysResult<[u8; Self::WIRE_LENGTH]> {
        self.validate(u64::MAX)?;
        let mut bytes = [0; Self::WIRE_LENGTH];
        bytes[..4].copy_from_slice(&Self::MAGIC);
        bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&(Self::WIRE_LENGTH as u16).to_le_bytes());
        bytes[16..24].copy_from_slice(&self.offset.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.length.to_le_bytes());
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> SysResult<Self> {
        if bytes.len() != Self::WIRE_LENGTH
            || bytes[..4] != Self::MAGIC
            || bytes[4..6] != 1u16.to_le_bytes()
            || bytes[6..8] != (Self::WIRE_LENGTH as u16).to_le_bytes()
            || bytes[8..16].iter().any(|byte| *byte != 0)
        {
            return Err(SysError::from_raw(syscall::EINVAL as i64));
        }
        let offer = Self {
            offset: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            length: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        };
        offer.validate(u64::MAX)?;
        Ok(offer)
    }

    fn validate(self, extent: u64) -> SysResult<()> {
        if self.offset % PAGE_BYTES != 0
            || self.length == 0
            || !self
                .offset
                .checked_add(self.length)
                .is_some_and(|end| end <= extent)
        {
            return Err(SysError::from_raw(syscall::EINVAL as i64));
        }
        Ok(())
    }
}

/// Consume one explicitly received RAM object and map it read-only. Callers
/// establish sender identity and attachment-count policy before calling this.
/// Errors close the received handle; a successful view owns its local mapping.
pub fn receive_readonly_offer(
    bytes: &[u8],
    object: MemoryObject,
    maximum_length: u64,
) -> SysResult<MemoryMapping> {
    let offer = ReadOnlyOffer::decode(bytes)?;
    if offer.length > maximum_length || object.rights()? != READONLY_BUFFER_RIGHTS {
        return Err(SysError::from_raw(syscall::EACCES as i64));
    }
    // This query checks resource type instead of trusting a descriptor's
    // claimed type or bounds. No sender FD/PID is looked up.
    offer.validate(object.length()?)?;
    object.map(offer.offset, offer.length, syscall::MEMORY_ACCESS_READ)
}

pub struct MemoryObject {
    handle: handle::Handle,
}

impl MemoryObject {
    /// Create fixed, page-aligned RAM backing using the current native ABI.
    pub fn create(length: u64) -> SysResult<Self> {
        if length == 0 || length % PAGE_BYTES != 0 {
            return Err(SysError::from_raw(syscall::EINVAL as i64));
        }
        Self::create_with_options(length, 0)
    }

    /// Create byte-sized, possibly empty RAM backing with extent CONTROL.
    /// Mappings reserve capacity independently of the current backing length.
    pub fn create_resizable(length: u64) -> SysResult<Self> {
        Self::create_with_options(length, syscall::MEMORY_OBJECT_RESIZABLE)
    }

    fn create_with_options(length: u64, options: u64) -> SysResult<Self> {
        let raw = syscall::call2(SyscallNumber::MemoryObjectCreate, length, options)?;
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

    /// Change the logical extent. Requires CONTROL on this process-local
    /// Handle. Shrink invalidates affected pages of existing mappings;
    /// subsequent access beyond the live extent faults. Regrowth is zeroed.
    pub fn resize(&self, length: u64) -> SysResult<()> {
        syscall::call2(SyscallNumber::MemoryObjectResize, self.handle as u64, length).map(|_| ())
    }

    pub fn rights(&self) -> SysResult<u64> {
        handle::rights(self.handle)
    }

    /// Attach READ|MAP only, without write, duplicate, control or re-transfer.
    /// The kernel enforces attenuation against this source handle's rights.
    pub fn send_readonly(&self, endpoint: u64, offset: u64, length: u64) -> SysResult<()> {
        let offer = ReadOnlyOffer { offset, length };
        offer.validate(self.length()?)?;
        let bytes = offer.encode()?;
        let mut handles = crate::ipc::IpcObjectHandles::default();
        handles.count = 1;
        handles.handles[0].handle = self.handle;
        handles.handles[0].rights = READONLY_BUFFER_RIGHTS;
        crate::ipc::send_object_handles(endpoint, &bytes, &handles).map(|_| ())
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
