//! Owned initialized storage shared by vector I/O and name-service snapshots.
use super::*;

pub(super) struct VectorBuffer {
    pub(super) pointer: *mut u8,
    pub(super) length: usize,
}

impl VectorBuffer {
    pub(super) fn new(total: usize) -> Result<Self, c_int> {
        let length = total.min(mochios_posix_client::io_vector::MAX_TRANSFER_BYTES);
        // newlib owns allocation; the freestanding runtime has no Rust allocator.
        let pointer = if length == 0 {
            core::ptr::NonNull::<u8>::dangling().as_ptr()
        } else {
            let pointer = unsafe { malloc(length) }.cast::<u8>();
            if pointer.is_null() {
                return Err(ENOMEM);
            }
            // Initialize storage before forming a safe Rust slice.
            unsafe { ptr::write_bytes(pointer, 0, length) };
            pointer
        };
        Ok(Self { pointer, length })
    }

    pub(super) fn bytes(&mut self) -> &mut [u8] {
        // Safety: owned, initialized allocation (or aligned dangling pointer for zero).
        unsafe { core::slice::from_raw_parts_mut(self.pointer, self.length) }
    }
}

impl Drop for VectorBuffer {
    fn drop(&mut self) {
        if self.length != 0 {
            unsafe { free(self.pointer.cast()) };
        }
    }
}
