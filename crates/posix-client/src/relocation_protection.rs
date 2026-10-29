//! User-space protection transaction around deferred relocations. Data-only
//! mappings may request temporary RW/NX access, followed by read-only access.
//! Records grant no VM authority; native mapping rights remain authoritative.
use core::sync::atomic::{AtomicU8, Ordering};
pub const MAGIC: u64 = u64::from_le_bytes(*b"MRELRO01");
pub const HEADER_BYTES: usize = 32;
pub const WRITABLE_HEADER_BYTES: usize = 40;
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
fn size<E>(count: usize, writable: usize, inner: usize) -> Result<usize, Error<E>> {
    if count == 0
        || count > u32::MAX as usize
        || writable > u32::MAX as usize
        || inner % 8 != 0
        || (writable != 0 && inner < crate::indirect_image::HEADER_BYTES)
    {
        return Err(Error::Invalid);
    }
    count
        .checked_add(writable)
        .and_then(|n| n.checked_mul(RANGE_BYTES))
        .and_then(|n| {
            n.checked_add(if writable == 0 {
                HEADER_BYTES
            } else {
                WRITABLE_HEADER_BYTES
            })
        })
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
/// Sort and combine valid page ranges, preserving all covered pages.
pub fn merge(items: &mut [Range]) -> Result<usize, Error> {
    for item in items.iter() {
        ranges(core::iter::once(*item))?;
    }
    items.sort_unstable_by_key(|r| r.address);
    let mut count = 0;
    for i in 0..items.len() {
        let r = items[i];
        if count != 0 && r.address <= items[count - 1].address + items[count - 1].length {
            let end =
                (r.address + r.length).max(items[count - 1].address + items[count - 1].length);
            items[count - 1].length = end - items[count - 1].address;
        } else {
            items[count] = r;
            count += 1;
        }
    }
    Ok(count)
}
pub fn encoded_length(count: usize, inner: usize) -> Result<usize, Error> {
    size(count, 0, inner)
}
pub fn encoded_length_with_writable(
    count: usize,
    writable: usize,
    inner: usize,
) -> Result<usize, Error> {
    size(count, writable, inner)
}
pub fn wrap(inner: usize, items: &[Range], output: &mut [u8]) -> Result<usize, Error> {
    wrap_with_writable(inner, items, &[], output)
}
/// Each temporary writable range must be completely restored by the final
/// read-only ranges. All validation precedes the in-place move.
pub fn wrap_with_writable(
    inner: usize,
    items: &[Range],
    writable: &[Range],
    output: &mut [u8],
) -> Result<usize, Error> {
    let length = size(items.len(), writable.len(), inner)?;
    if length > output.len() {
        return Err(Error::TooLarge);
    }
    ranges(items.iter().copied())?;
    ranges(writable.iter().copied())?;
    if writable.iter().any(|w| {
        !items
            .iter()
            .any(|r| r.address <= w.address && w.address + w.length <= r.address + r.length)
    }) {
        return Err(Error::Invalid);
    }
    if inner != 0
        && (inner < crate::indirect_image::HEADER_BYTES
            || word(output, 0) != crate::indirect_image::MAGIC)
    {
        return Err(Error::Invalid);
    }
    let version = if writable.is_empty() { 1 } else { 2 };
    let header = if version == 1 {
        HEADER_BYTES
    } else {
        WRITABLE_HEADER_BYTES
    };
    let start = length - inner;
    output.copy_within(..inner, start);
    output[..start].fill(0);
    for (at, value) in [
        (0, MAGIC),
        (8, version | ((items.len() as u64) << 32)),
        (16, length as u64),
        (24, inner as u64),
    ] {
        output[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    if version == 2 {
        output[32..40].copy_from_slice(&(writable.len() as u64).to_le_bytes());
    }
    for (i, r) in items.iter().chain(writable).enumerate() {
        let at = header + i * RANGE_BYTES;
        output[at..at + 8].copy_from_slice(&r.address.to_le_bytes());
        output[at + 8..at + 16].copy_from_slice(&r.length.to_le_bytes());
    }
    Ok(length)
}
fn header_bytes<E>(b: &[u8]) -> Result<usize, Error<E>> {
    if b.len() < HEADER_BYTES || word(b, 0) != MAGIC {
        return Err(Error::Invalid);
    }
    match word(b, 8) as u32 {
        1 => Ok(HEADER_BYTES),
        2 => Ok(WRITABLE_HEADER_BYTES),
        _ => Err(Error::Invalid),
    }
}
fn header<E>(b: &[u8], maximum: usize) -> Result<(usize, usize, usize), Error<E>> {
    let h = header_bytes(b)?;
    if b.len() < h {
        return Err(Error::Invalid);
    }
    let writable = if h == HEADER_BYTES {
        0
    } else {
        usize::try_from(word(b, 32)).map_err(|_| Error::TooLarge)?
    };
    if h != HEADER_BYTES && writable == 0 {
        return Err(Error::Invalid);
    }
    let inner = usize::try_from(word(b, 24)).map_err(|_| Error::TooLarge)?;
    let length = size((word(b, 8) >> 32) as usize, writable, inner)?;
    if word(b, 16) != length as u64 {
        return Err(Error::Invalid);
    }
    if length > maximum {
        return Err(Error::TooLarge);
    }
    Ok((length, inner, writable))
}
fn read_header<E>(
    base: u64,
    maximum: usize,
    b: &mut [u8; WRITABLE_HEADER_BYTES],
    read: &mut impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<(usize, usize), Error<E>> {
    if base < 0x400000
        || base % 8 != 0
        || base
            .checked_add(HEADER_BYTES as u64)
            .is_none_or(|n| n > USER_END)
    {
        return Err(Error::Invalid);
    }
    read(base, &mut b[..HEADER_BYTES]).map_err(Error::Read)?;
    let h = header_bytes(b)?;
    if base.checked_add(h as u64).is_none_or(|n| n > USER_END) {
        return Err(Error::Invalid);
    }
    if h > HEADER_BYTES {
        read(base + HEADER_BYTES as u64, &mut b[HEADER_BYTES..h]).map_err(Error::Read)?;
    }
    let (length, _, _) = header(b, maximum)?;
    if base.checked_add(length as u64).is_none_or(|n| n > USER_END) {
        return Err(Error::Invalid);
    }
    Ok((length, h))
}
pub fn length<E>(
    base: u64,
    maximum: usize,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<usize, Error<E>> {
    let mut b = [0; WRITABLE_HEADER_BYTES];
    read_header(base, maximum, &mut b, &mut read).map(|(n, _)| n)
}
pub fn capture<E>(
    base: u64,
    maximum: usize,
    output: &mut [u8],
    mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<usize, Error<E>> {
    let mut b = [0; WRITABLE_HEADER_BYTES];
    let (length, h) = read_header(base, maximum, &mut b, &mut read)?;
    if output.len() < length {
        return Err(Error::TooLarge);
    }
    output[..h].copy_from_slice(&b[..h]);
    read(base + h as u64, &mut output[h..length]).map_err(Error::Read)?;
    Image::parse::<E>(&output[..length])?;
    Ok(length)
}
pub struct Image<'a> {
    bytes: &'a [u8],
    inner: usize,
    writable: usize,
    header: usize,
}
impl<'a> Image<'a> {
    pub fn parse<E>(bytes: &'a [u8]) -> Result<Self, Error<E>> {
        let (length, inner, writable) = header(bytes, bytes.len())?;
        if length != bytes.len() {
            return Err(Error::Invalid);
        }
        let image = Self {
            bytes,
            inner,
            writable,
            header: header_bytes(bytes)?,
        };
        ranges(image.ranges())?;
        ranges(image.writable_ranges())?;
        if image.writable_ranges().any(|w| {
            !image
                .ranges()
                .any(|r| r.address <= w.address && w.address + w.length <= r.address + r.length)
        }) {
            return Err(Error::Invalid);
        }
        if inner != 0
            && (inner < crate::indirect_image::HEADER_BYTES
                || word(image.indirect(), 0) != crate::indirect_image::MAGIC)
        {
            return Err(Error::Invalid);
        }
        Ok(image)
    }
    fn records(&self, start: usize, end: usize) -> impl Iterator<Item = Range> + '_ {
        self.bytes[start..end]
            .chunks_exact(RANGE_BYTES)
            .map(|b| Range {
                address: word(b, 0),
                length: word(b, 8),
            })
    }
    pub fn ranges(&self) -> impl Iterator<Item = Range> + '_ {
        self.records(
            self.header,
            self.inner_offset() - self.writable * RANGE_BYTES,
        )
    }
    pub fn writable_ranges(&self) -> impl Iterator<Item = Range> + '_ {
        self.records(
            self.inner_offset() - self.writable * RANGE_BYTES,
            self.inner_offset(),
        )
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
        protect: impl FnMut(Range) -> Result<(), E>,
    ) -> Result<(), Error<E>> {
        if image.writable != 0 {
            return Err(Error::Invalid);
        }
        self.execute(image, |image| relocate(image.indirect()), protect)
    }
    /// The callback first captures and validates the complete inner plan, then
    /// enables exactly writable_ranges before invoking any resolver. It must
    /// also own rollback for failures before final protection completes.
    pub fn apply_with_writable<E>(
        &self,
        image: &Image<'_>,
        relocate: impl FnOnce(&Image<'_>) -> Result<(), E>,
        protect: impl FnMut(Range) -> Result<(), E>,
    ) -> Result<(), Error<E>> {
        self.execute(image, relocate, protect)
    }
    fn execute<E>(
        &self,
        image: &Image<'_>,
        relocate: impl FnOnce(&Image<'_>) -> Result<(), E>,
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
            relocate(image).map_err(Error::Relocate)?;
        }
        for range in image.ranges() {
            protect(range).map_err(Error::Protect)?;
        }
        core::mem::forget(attempt);
        self.0.store(2, Ordering::Release);
        Ok(())
    }
}
