//! Owned iovec addresses/lengths. Common small vectors require no allocation;
//! overflow storage belongs to the enclosing nonlocal-callback resource scope.
use super::*;

const INLINE: usize = 8;

#[derive(Clone, Copy)]
struct Part {
    base: *mut c_void,
    length: usize,
}

pub(super) struct VectorMetadata {
    inline: [Part; INLINE],
    overflow: *mut Part,
    count: usize,
}

impl VectorMetadata {
    pub(super) fn new(count: usize) -> Result<Self, c_int> {
        if count > mochios_posix_client::io_vector::IOV_MAX {
            return Err(EINVAL);
        }
        let overflow = if count > INLINE {
            // Count is bounded by IOV_MAX. newlib malloc supplies alignment
            // for Part. Zero represents a valid empty Part, including on a
            // failed/abandoned capture before all entries have been copied.
            let bytes = (count - INLINE) * core::mem::size_of::<Part>();
            let pointer = unsafe { malloc(bytes) };
            if pointer.is_null() {
                return Err(ENOMEM);
            }
            unsafe { ptr::write_bytes(pointer.cast::<u8>(), 0, bytes) };
            pointer.cast()
        } else {
            ptr::null_mut()
        };
        Ok(Self {
            inline: [Part {
                base: ptr::null_mut(),
                length: 0,
            }; INLINE],
            overflow,
            count,
        })
    }

    pub(super) fn set(&mut self, index: usize, base: *mut c_void, length: usize) {
        assert!(index < self.count);
        let part = Part { base, length };
        if index < INLINE {
            self.inline[index] = part;
        } else {
            // The enclosing scope remains pinned throughout capture.
            unsafe { self.overflow.add(index - INLINE).write(part) };
        }
    }

    /// Capture/validation must have initialized every entry before I/O starts.
    pub(super) fn get(&self, index: usize) -> (*mut c_void, usize) {
        assert!(index < self.count);
        let part = if index < INLINE {
            self.inline[index]
        } else {
            unsafe { self.overflow.add(index - INLINE).read() }
        };
        (part.base, part.length)
    }
}

impl Drop for VectorMetadata {
    fn drop(&mut self) {
        if !self.overflow.is_null() {
            unsafe { free(self.overflow.cast()) };
        }
    }
}
