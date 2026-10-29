//! Userspace-only lifecycle image. No native kernel ABI or pointers to the
//! producer's address space are involved. Addresses name the prepared child.
use core::sync::atomic::{AtomicUsize, Ordering};
pub mod deferred;

pub const MAGIC: u64 = u64::from_le_bytes(*b"MLIFE001");
pub const VERSION: u32 = 1;
pub const HEADER_BYTES: usize = 32;
pub const OBJECT_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error<E> {
    Invalid,
    TooLarge,
    Read(E),
}

#[derive(Clone, Copy, Debug)]
pub struct Callbacks {
    offset: usize,
    count: usize,
}
#[derive(Clone, Copy, Debug)]
pub struct Object {
    pub initialize: Callbacks,
    pub finalize: Callbacks,
}
#[derive(Clone, Copy, Debug)]
pub struct Image {
    base: u64,
    length: usize,
    objects: usize,
    preinit: Callbacks,
}

fn word<E>(
    base: u64,
    offset: usize,
    read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<u64, Error<E>> {
    let address = base.checked_add(offset as u64).ok_or(Error::Invalid)?;
    address.checked_add(8).ok_or(Error::Invalid)?;
    let mut bytes = [0; 8];
    read(address, &mut bytes).map_err(Error::Read)?;
    Ok(u64::from_le_bytes(bytes))
}

impl Image {
    pub fn read<E>(
        base: u64,
        maximum: usize,
        mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
    ) -> Result<Self, Error<E>> {
        if base == 0 || base % 8 != 0 || maximum < HEADER_BYTES {
            return Err(Error::Invalid);
        }
        if word(base, 0, &mut read)? != MAGIC {
            return Err(Error::Invalid);
        }
        let format = word(base, 8, &mut read)?;
        if format as u32 != VERSION {
            return Err(Error::Invalid);
        }
        let objects = (format >> 32) as usize;
        let length = usize::try_from(word(base, 16, &mut read)?).map_err(|_| Error::TooLarge)?;
        let preinit_count =
            usize::try_from(word(base, 24, &mut read)?).map_err(|_| Error::TooLarge)?;
        if length > maximum {
            return Err(Error::TooLarge);
        }
        base.checked_add(length as u64).ok_or(Error::Invalid)?;
        let start = objects
            .checked_mul(OBJECT_BYTES)
            .and_then(|bytes| bytes.checked_add(HEADER_BYTES))
            .ok_or(Error::Invalid)?;
        if objects == 0 || start > length {
            return Err(Error::Invalid);
        }
        let image = Self {
            base,
            length,
            objects,
            preinit: Callbacks {
                offset: start,
                count: preinit_count,
            },
        };
        let mut cursor = image.end(image.preinit)?;
        for index in 0..objects {
            let object = image.object(index, &mut read)?;
            if object.initialize.offset != cursor {
                return Err(Error::Invalid);
            }
            cursor = image.end(object.initialize)?;
            if object.finalize.offset != cursor {
                return Err(Error::Invalid);
            }
            cursor = image.end(object.finalize)?;
        }
        if cursor != length {
            return Err(Error::Invalid);
        }
        // Validate all encoded pointers before the first initializer runs.
        for offset in (start..length).step_by(8) {
            let address = word(base, offset, &mut read)?;
            if address == 0 || usize::try_from(address).is_err() {
                return Err(Error::Invalid);
            }
        }
        Ok(image)
    }

    fn end<E>(&self, calls: Callbacks) -> Result<usize, Error<E>> {
        let end = calls
            .count
            .checked_mul(8)
            .and_then(|bytes| calls.offset.checked_add(bytes))
            .filter(|end| *end <= self.length)
            .ok_or(Error::Invalid)?;
        if calls.offset < self.preinit.offset || calls.offset % 8 != 0 {
            return Err(Error::Invalid);
        }
        Ok(end)
    }

    pub fn object<E>(
        &self,
        index: usize,
        mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
    ) -> Result<Object, Error<E>> {
        if index >= self.objects {
            return Err(Error::Invalid);
        }
        let offset = HEADER_BYTES + index * OBJECT_BYTES;
        let mut field = |delta| {
            usize::try_from(word(self.base, offset + delta, &mut read)?).map_err(|_| Error::Invalid)
        };
        let object = Object {
            initialize: Callbacks {
                offset: field(0)?,
                count: field(8)?,
            },
            finalize: Callbacks {
                offset: field(16)?,
                count: field(24)?,
            },
        };
        self.end(object.initialize)?;
        self.end(object.finalize)?;
        Ok(object)
    }

    fn visit<E>(
        &self,
        calls: Callbacks,
        read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), E>,
        call: &mut impl FnMut(u64) -> Result<(), E>,
    ) -> Result<(), Error<E>> {
        self.end(calls)?;
        for index in 0..calls.count {
            let address = word(self.base, calls.offset + index * 8, read)?;
            if address == 0 {
                return Err(Error::Invalid);
            }
            call(address).map_err(Error::Read)?;
        }
        Ok(())
    }
}

/// Per-image state. No lock is held while callbacks execute or call exit.
/// fork inherits both this state and the image's original stack mapping.
pub struct State {
    phase: AtomicUsize,
}
impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
impl State {
    pub const fn new() -> Self {
        Self {
            phase: AtomicUsize::new(0),
        }
    }
    pub fn initialize<E>(
        &self,
        image: &Image,
        mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
        mut call: impl FnMut(u64) -> Result<(), E>,
    ) -> Result<(), Error<E>> {
        match self
            .phase
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(value) if value & 7 == 2 => return Ok(()),
            Err(_) => return Err(Error::Invalid),
        }
        image.visit(image.preinit, &mut read, &mut call)?;
        for index in 0..image.objects {
            let object = image.object(index, &mut read)?;
            // Mark before calling: exit from this object's initializer must
            // finalize this object, but never a not-yet-started dependent.
            self.phase
                .compare_exchange(
                    1 | (index << 3),
                    1 | ((index + 1) << 3),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .map_err(|_| Error::Invalid)?;
            image.visit(object.initialize, &mut read, &mut call)?;
        }
        self.phase
            .compare_exchange(
                1 | (image.objects << 3),
                2 | (image.objects << 3),
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| Error::Invalid)?;
        Ok(())
    }

    pub fn finalize<E>(
        &self,
        image: &Image,
        mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
        mut call: impl FnMut(u64) -> Result<(), E>,
    ) -> Result<(), Error<E>> {
        let begun = loop {
            let value = self.phase.load(Ordering::Acquire);
            let phase = value & 7;
            if phase == 0 || phase >= 3 {
                return Ok(());
            }
            if self
                .phase
                .compare_exchange(value, 3 | (value & !7), Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break value >> 3;
            }
        };
        if begun > image.objects {
            return Err(Error::Invalid);
        }
        for index in (0..begun).rev() {
            let object = image.object(index, &mut read)?;
            image.visit(object.finalize, &mut read, &mut call)?;
        }
        self.phase.store(4, Ordering::Release);
        Ok(())
    }
}
