//! User-space RELRO transaction around an optional deferred relocation plan.
//! These records only request read-only protection; they grant no VM authority.
use core::sync::atomic::{AtomicU8, Ordering};
pub const MAGIC: u64 = u64::from_le_bytes(*b"MRELRO01");
pub const HEADER_BYTES: usize = 32;
pub const RANGE_BYTES: usize = 16;
const PAGE: u64 = 4096;
const USER_END: u64 = 0x8000_0000_0000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub address: u64,
    pub length: u64,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E = core::convert::Infallible> {
    Invalid,
    TooLarge,
    Read(E),
    Relocate(E),
    Protect(E),
    Reentrant,
    Failed,
}
fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn size<E>(count: usize, inner: usize) -> Result<usize, Error<E>> {
    if count == 0 || count > u32::MAX as usize || inner % 8 != 0 {
        return Err(Error::Invalid);
    }
    count
        .checked_mul(RANGE_BYTES)
        .and_then(|n| n.checked_add(HEADER_BYTES))
        .and_then(|n| n.checked_add(inner))
        .ok_or(Error::TooLarge)
}
fn ranges<E>(items: impl Iterator<Item = Range>) -> Result<(), Error<E>> {
    let mut end = 0x400000;
    for r in items {
        if r.address < end || r.address % PAGE != 0 || r.length == 0 || r.length % PAGE != 0 {
            return Err(Error::Invalid);
        }
        end = r
            .address
            .checked_add(r.length)
            .filter(|n| *n <= USER_END)
            .ok_or(Error::Invalid)?;
    }
    Ok(())
}
pub fn encoded_length(count: usize, inner: usize) -> Result<usize, Error> {
    size(count, inner)
}
/// All checks precede the in-place move. The inner plan is produced and
/// validated separately by indirect_image, then captured again by the CRT.
pub fn wrap(inner: usize, items: &[Range], output: &mut [u8]) -> Result<usize, Error> {
    let length = size(items.len(), inner)?;
    if length > output.len() {
        return Err(Error::TooLarge);
    }
    ranges(items.iter().copied())?;
    if inner != 0
        && (inner < crate::indirect_image::HEADER_BYTES
            || word(output, 0) != crate::indirect_image::MAGIC)
    {
        return Err(Error::Invalid);
    }
    let start = length - inner;
    output.copy_within(..inner, start);
    output[..start].fill(0);
    for (at, value) in [
        (0, MAGIC),
        (8, 1 | ((items.len() as u64) << 32)),
        (16, length as u64),
        (24, inner as u64),
    ] {
        output[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    for (i, r) in items.iter().enumerate() {
        let at = HEADER_BYTES + i * RANGE_BYTES;
        output[at..at + 8].copy_from_slice(&r.address.to_le_bytes());
        output[at + 8..at + 16].copy_from_slice(&r.length.to_le_bytes());
    }
    Ok(length)
}
fn header<E>(b: &[u8], maximum: usize) -> Result<(usize, usize), Error<E>> {
    if b.len() < HEADER_BYTES || word(b, 0) != MAGIC || word(b, 8) as u32 != 1 {
        return Err(Error::Invalid);
    }
    let inner = usize::try_from(word(b, 24)).map_err(|_| Error::TooLarge)?;
    let length = size((word(b, 8) >> 32) as usize, inner)?;
    if word(b, 16) != length as u64 {
        return Err(Error::Invalid);
    }
    if length > maximum {
        return Err(Error::TooLarge);
    }
    Ok((length, inner))
}
pub fn length<E>(
    base: u64,
    maximum: usize,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<usize, Error<E>> {
    if base < 0x400000
        || base % 8 != 0
        || base
            .checked_add(HEADER_BYTES as u64)
            .is_none_or(|n| n > USER_END)
    {
        return Err(Error::Invalid);
    }
    let mut b = [0; HEADER_BYTES];
    read(base, &mut b).map_err(Error::Read)?;
    let (length, _) = header(&b, maximum)?;
    if base.checked_add(length as u64).is_none_or(|n| n > USER_END) {
        return Err(Error::Invalid);
    }
    Ok(length)
}
pub fn capture<E>(
    base: u64,
    maximum: usize,
    output: &mut [u8],
    mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<usize, Error<E>> {
    let mut b = [0; HEADER_BYTES];
    let length = length(base, maximum, |a, out| {
        read(a, out)?;
        b.copy_from_slice(out);
        Ok(())
    })?;
    if output.len() < length {
        return Err(Error::TooLarge);
    }
    output[..HEADER_BYTES].copy_from_slice(&b);
    read(
        base + HEADER_BYTES as u64,
        &mut output[HEADER_BYTES..length],
    )
    .map_err(Error::Read)?;
    Image::parse::<E>(&output[..length])?;
    Ok(length)
}
pub struct Image<'a> {
    bytes: &'a [u8],
    inner: usize,
}
impl<'a> Image<'a> {
    pub fn parse<E>(bytes: &'a [u8]) -> Result<Self, Error<E>> {
        let (length, inner) = header(bytes, bytes.len())?;
        if length != bytes.len() {
            return Err(Error::Invalid);
        }
        let image = Self { bytes, inner };
        ranges(image.ranges())?;
        if inner != 0
            && (inner < crate::indirect_image::HEADER_BYTES
                || word(image.indirect(), 0) != crate::indirect_image::MAGIC)
        {
            return Err(Error::Invalid);
        }
        Ok(image)
    }
    pub fn ranges(&self) -> impl Iterator<Item = Range> + '_ {
        self.bytes[HEADER_BYTES..self.inner_offset()]
            .chunks_exact(RANGE_BYTES)
            .map(|b| Range {
                address: word(b, 0),
                length: word(b, 8),
            })
    }
    pub fn inner_offset(&self) -> usize {
        self.bytes.len() - self.inner
    }
    pub fn indirect(&self) -> &'a [u8] {
        &self.bytes[self.inner_offset()..]
    }
}
pub struct State(AtomicU8);
impl State {
    pub const fn new() -> Self {
        Self(AtomicU8::new(0))
    }
    pub fn status<E>(&self) -> Result<bool, Error<E>> {
        match self.0.load(Ordering::Acquire) {
            0 => Ok(false),
            2 => Ok(true),
            3 => Err(Error::Failed),
            _ => Err(Error::Reentrant),
        }
    }
    /// All storage and the complete plan must be captured before this call.
    /// A protection failure is terminal, including after partial protection.
    pub fn apply<E>(
        &self,
        image: &Image<'_>,
        relocate: impl FnOnce(&[u8]) -> Result<(), E>,
        mut protect: impl FnMut(Range) -> Result<(), E>,
    ) -> Result<(), Error<E>> {
        match self
            .0
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
        let attempt = Attempt(&self.0);
        if !image.indirect().is_empty() {
            relocate(image.indirect()).map_err(Error::Relocate)?;
        }
        for range in image.ranges() {
            protect(range).map_err(Error::Protect)?;
        }
        core::mem::forget(attempt);
        self.0.store(2, Ordering::Release);
        Ok(())
    }
}
