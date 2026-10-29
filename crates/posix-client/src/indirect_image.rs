//! Deferred ELF resolver records for the receiving image's userspace runtime.
//! Region declarations describe an already installed, authorized image; they
//! neither grant mapping rights nor authorize code in another process.
use core::{
    convert::Infallible,
    sync::atomic::{AtomicU8, Ordering},
};

pub const MAGIC: u64 = u64::from_le_bytes(*b"MIREL001");
pub const VERSION: u32 = 1;
pub const HEADER_BYTES: usize = 40;
pub const REGION_BYTES: usize = 24;
pub const FIXUP_BYTES: usize = 32;
const USER_MIN: u64 = 0x0040_0000;
const USER_END: u64 = 0x0000_8000_0000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error<E = Infallible> {
    Invalid,
    TooLarge,
    BufferTooSmall,
    Read(E),
    Resolve(E),
    Write(E),
    Reentrant,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Executable,
    Writable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub address: u64,
    pub length: u64,
    pub access: Access,
}
impl Region {
    pub const EMPTY: Self = Self {
        address: 0,
        length: 0,
        access: Access::Executable,
    };
    fn end<E>(self) -> Result<u64, Error<E>> {
        self.address
            .checked_add(self.length)
            .filter(|end| self.address >= USER_MIN && self.length != 0 && *end <= USER_END)
            .ok_or(Error::Invalid)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fixup {
    target: u64,
    resolver: u64,
    addend: u64,
    order: usize,
}
impl Fixup {
    pub const EMPTY: Self = Self::new(0, 0, 0);
    /// IRELATIVE uses the rebased resolver address and a post-call addend of
    /// zero. A symbolic absolute IFUNC reference retains its relocation addend.
    pub const fn new(target: u64, resolver: u64, addend: u64) -> Self {
        Self {
            target,
            resolver,
            addend,
            order: 0,
        }
    }
    pub fn target(self) -> u64 {
        self.target
    }
    pub fn resolver(self) -> u64 {
        self.resolver
    }
    pub fn addend(self) -> u64 {
        self.addend
    }
}
fn length<E>(regions: usize, fixups: usize) -> Result<usize, Error<E>> {
    u32::try_from(regions).map_err(|_| Error::TooLarge)?;
    regions
        .checked_mul(REGION_BYTES)
        .and_then(|n| n.checked_add(HEADER_BYTES))
        .and_then(|n| fixups.checked_mul(FIXUP_BYTES)?.checked_add(n))
        .ok_or(Error::TooLarge)
}

/// Required storage for an encoded plan, without allocating or reading it.
pub fn encoded_length(regions: usize, fixups: usize) -> Result<usize, Error> {
    length(regions, fixups)
}
fn contains(regions: &[Region], address: u64, width: u64, access: Access) -> bool {
    let index = regions.partition_point(|r| r.address <= address);
    if index == 0 {
        return false;
    }
    let r = regions[index - 1];
    r.access == access
        && address
            .checked_add(width)
            .is_some_and(|end| end <= r.address + r.length)
}
fn validate<E>(regions: &[Region], fixups: &mut [Fixup]) -> Result<(), Error<E>> {
    let mut end = USER_MIN;
    for r in regions {
        if r.address < end {
            return Err(Error::Invalid);
        }
        end = r.end()?;
    }
    for (index, f) in fixups.iter_mut().enumerate() {
        if !contains(regions, f.target, 8, Access::Writable)
            || !contains(regions, f.resolver, 1, Access::Executable)
        {
            return Err(Error::Invalid);
        }
        f.order = index;
    }
    // Check all intervals without a quadratic scan, then restore callback
    // order even on failure. Resolver order is observable application behavior.
    fixups.sort_unstable_by_key(|f| f.target);
    let overlap = fixups
        .windows(2)
        .any(|pair| pair[1].target < pair[0].target + 8);
    fixups.sort_unstable_by_key(|f| f.order);
    if overlap {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn put(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Encode child virtual addresses after ordinary relocations and authority
/// checks. Regions must be sorted and disjoint. Fixups retain their input order.
/// No resolver code is called by this producer.
pub fn encode(regions: &[Region], fixups: &mut [Fixup], out: &mut [u8]) -> Result<usize, Error> {
    let size = length(regions.len(), fixups.len())?;
    if out.len() < size {
        return Err(Error::BufferTooSmall);
    }
    validate(regions, fixups)?;
    let out = &mut out[..size];
    out.fill(0);
    put(out, 0, MAGIC);
    put(out, 8, u64::from(VERSION) | ((regions.len() as u64) << 32));
    put(out, 16, fixups.len() as u64);
    put(out, 24, size as u64);
    for (index, r) in regions.iter().enumerate() {
        let at = HEADER_BYTES + index * REGION_BYTES;
        put(out, at, r.address);
        put(out, at + 8, r.length);
        put(
            out,
            at + 16,
            match r.access {
                Access::Executable => 1,
                Access::Writable => 2,
            },
        );
    }
    let start = HEADER_BYTES + regions.len() * REGION_BYTES;
    for (index, f) in fixups.iter().enumerate() {
        let at = start + index * FIXUP_BYTES;
        put(out, at, f.target);
        put(out, at + 8, f.resolver);
        put(out, at + 16, f.addend);
    }
    Ok(size)
}
fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

/// A complete private snapshot. No reference to the input metadata survives
/// capture, so a resolver cannot redirect later fixups by changing that input.
pub struct Captured<'a> {
    fixups: &'a [Fixup],
}
impl<'a> Captured<'a> {
    pub fn capture<E>(
        base: u64,
        maximum: usize,
        region_storage: &mut [Region],
        fixup_storage: &'a mut [Fixup],
        mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
    ) -> Result<Self, Error<E>> {
        if base < USER_MIN || base % 8 != 0 || maximum < HEADER_BYTES {
            return Err(Error::Invalid);
        }
        base.checked_add(HEADER_BYTES as u64)
            .filter(|end| *end <= USER_END)
            .ok_or(Error::Invalid)?;
        let mut header = [0; HEADER_BYTES];
        read(base, &mut header).map_err(Error::Read)?;
        let format = word(&header, 8);
        if word(&header, 0) != MAGIC || format as u32 != VERSION || word(&header, 32) != 0 {
            return Err(Error::Invalid);
        }
        let regions = (format >> 32) as usize;
        let fixups = usize::try_from(word(&header, 16)).map_err(|_| Error::TooLarge)?;
        let size = length(regions, fixups)?;
        if size > maximum {
            return Err(Error::TooLarge);
        }
        if word(&header, 24) != size as u64 {
            return Err(Error::Invalid);
        }
        base.checked_add(size as u64)
            .filter(|end| *end <= USER_END)
            .ok_or(Error::Invalid)?;
        if region_storage.len() < regions || fixup_storage.len() < fixups {
            return Err(Error::BufferTooSmall);
        }
        let regions = &mut region_storage[..regions];
        let fixups = &mut fixup_storage[..fixups];
        for (index, r) in regions.iter_mut().enumerate() {
            let mut bytes = [0; REGION_BYTES];
            read(
                base + (HEADER_BYTES + index * REGION_BYTES) as u64,
                &mut bytes,
            )
            .map_err(Error::Read)?;
            *r = Region {
                address: word(&bytes, 0),
                length: word(&bytes, 8),
                access: match word(&bytes, 16) {
                    1 => Access::Executable,
                    2 => Access::Writable,
                    _ => return Err(Error::Invalid),
                },
            };
        }
        let start = HEADER_BYTES + regions.len() * REGION_BYTES;
        for (index, f) in fixups.iter_mut().enumerate() {
            let mut bytes = [0; FIXUP_BYTES];
            read(base + (start + index * FIXUP_BYTES) as u64, &mut bytes).map_err(Error::Read)?;
            if word(&bytes, 24) != 0 {
                return Err(Error::Invalid);
            }
            *f = Fixup::new(word(&bytes, 0), word(&bytes, 8), word(&bytes, 16));
        }
        validate(regions, fixups)?;
        Ok(Self { fixups })
    }
    pub fn len(&self) -> usize {
        self.fixups.len()
    }
    pub fn is_empty(&self) -> bool {
        self.fixups.is_empty()
    }
}

/// Once-only initial-image execution. Each state belongs to one initial image;
/// it must not be reused for a different plan or a later dlopen transaction.
/// The caller must run this in the image
/// whose code/data regions were captured, after ordinary relocations and TLS
/// setup, before constructors or application threads can use the fixup sites.
pub struct State {
    phase: AtomicU8,
}
impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}
impl State {
    pub const fn new() -> Self {
        Self {
            phase: AtomicU8::new(0),
        }
    }
    pub fn apply<E>(
        &self,
        image: &Captured<'_>,
        mut resolve: impl FnMut(u64) -> Result<u64, E>,
        mut write: impl FnMut(u64, &[u8]) -> Result<(), E>,
    ) -> Result<(), Error<E>> {
        match self
            .phase
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(2) => return Ok(()),
            Err(3) => return Err(Error::Failed),
            Err(_) => return Err(Error::Reentrant),
        }
        struct Attempt<'a>(&'a AtomicU8);
        impl Drop for Attempt<'_> {
            fn drop(&mut self) {
                self.0.store(3, Ordering::Release);
            }
        }
        let attempt = Attempt(&self.phase);
        for fixup in image.fixups {
            let value = resolve(fixup.resolver)
                .map_err(Error::Resolve)?
                .wrapping_add(fixup.addend);
            write(fixup.target, &value.to_le_bytes()).map_err(Error::Write)?;
        }
        core::mem::forget(attempt);
        self.phase.store(2, Ordering::Release);
        Ok(())
    }
}
