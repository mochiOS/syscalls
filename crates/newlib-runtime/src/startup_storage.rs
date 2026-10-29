//! Private, AS-limit-accounted scratch for metadata which cannot fit on the
//! entry stack. Only fresh runtime-owned mappings become Rust references.
use super::{E2BIG, EIO, NATIVE_READ_WRITE, PAGE_SIZE, address_space, c_int, syscall};
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __mochios_startup_metadata_v1() -> u64 {
    1
}
pub(super) struct Buffer {
    base: usize,
    length: usize,
    capacity: usize,
}
impl Buffer {
    pub(super) fn new(length: usize) -> Result<Self, c_int> {
        let capacity = length
            .checked_add(PAGE_SIZE - 1)
            .map(|n| n & !(PAGE_SIZE - 1))
            .filter(|n| *n != 0 && *n <= 2 * mochios_posix_client::startup_metadata::MAX_BYTES)
            .ok_or(E2BIG)?;
        let base =
            address_space::current()?.map(0, capacity as u64, NATIVE_READ_WRITE, 0, 0, 0)? as usize;
        if base < PAGE_SIZE || base % PAGE_SIZE != 0 || base.checked_add(capacity).is_none() {
            return Err(EIO);
        }
        Ok(Self {
            base,
            length,
            capacity,
        })
    }
    pub(super) fn bytes(&self) -> &[u8] {
        // SAFETY: this owner retains the exact fresh readable mapping.
        unsafe { core::slice::from_raw_parts(self.base as *const u8, self.length) }
    }
    pub(super) fn capacity(&self) -> usize {
        self.capacity
    }
    pub(super) fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: exclusive access to this fresh writable mapping; no view escapes.
        unsafe { core::slice::from_raw_parts_mut(self.base as *mut u8, self.length) }
    }
    pub(super) fn into_raw(self) -> (usize, usize) {
        let result = (self.base, self.capacity);
        core::mem::forget(self);
        result
    }
    /// # Safety
    /// The pair comes from into_raw and its ownership has not been consumed.
    pub(super) unsafe fn release(base: usize, capacity: usize) {
        let _ = syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryUnmap,
            base as u64,
            capacity as u64,
        );
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe { Self::release(self.base, self.capacity) };
    }
}
