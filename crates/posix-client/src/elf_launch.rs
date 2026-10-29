//! Unrelocated ELF launch images for a userspace interpreter. The interpreter
//! owns dynamic linking; the native container owns only validated LOAD bytes.
use crate::process_image::Executable;
const PAGE: u64 = 4096;
const USER_MIN: u64 = 0x400000;
const USER_END: u64 = 0x8000_0000_0000;
const LOAD: u32 = 1;
const PHDR: u32 = 6;
const STACK: u32 = 0x6474e551;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Unsupported,
    TooLarge,
    ShortOutput,
}
fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b).ok_or(Error::TooLarge)
}
fn align(a: u64, b: u64) -> Result<u64, Error> {
    Ok(add(a, b - 1)? & !(b - 1))
}
fn extent(b: &[u8], at: u64, n: u64) -> Result<core::ops::Range<usize>, Error> {
    let end = usize::try_from(add(at, n)?).map_err(|_| Error::TooLarge)?;
    let at = usize::try_from(at).map_err(|_| Error::TooLarge)?;
    if end > b.len() {
        return Err(Error::Invalid);
    }
    Ok(at..end)
}
fn word(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
#[derive(Clone, Copy)]
pub(crate) struct Segment {
    pub(crate) kind: u32,
    pub(crate) flags: u32,
    pub(crate) offset: u64,
    pub(crate) address: u64,
    pub(crate) file: u64,
    pub(crate) memory: u64,
    alignment: u64,
}
impl Segment {
    fn write(self, b: &mut [u8], at: usize) {
        b[at..at + 4].copy_from_slice(&self.kind.to_le_bytes());
        b[at + 4..at + 8].copy_from_slice(&self.flags.to_le_bytes());
        for (i, v) in [
            self.offset,
            self.address,
            0,
            self.file,
            self.memory,
            self.alignment,
        ]
        .into_iter()
        .enumerate()
        {
            b[at + 8 + i * 8..at + 16 + i * 8].copy_from_slice(&v.to_le_bytes());
        }
    }
}
#[derive(Clone, Copy)]
pub struct Image<'a> {
    bytes: &'a [u8],
    phoff: usize,
    count: usize,
    fixed: bool,
    entry: u64,
    alignment: u64,
    minimum: u64,
    maximum: u64,
    loads: usize,
}
impl<'a> Image<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::parse_impl(bytes, true)
    }
    // A DSO need not have an executable entry. LOAD validation is identical;
    // installing bytes does not authorize entry or perform dynamic linking.
    pub(crate) fn parse_mapping(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::parse_impl(bytes, false)
    }
    fn parse_impl(bytes: &'a [u8], require_entry: bool) -> Result<Self, Error> {
        if bytes.len() < 64
            || bytes[..7] != [0x7f, b'E', b'L', b'F', 2, 1, 1]
            || !matches!(u16::from_le_bytes(bytes[16..18].try_into().unwrap()), 2 | 3)
            || u16::from_le_bytes(bytes[18..20].try_into().unwrap()) != 62
            || bytes[20..24] != 1u32.to_le_bytes()
            || bytes[52..54] != 64u16.to_le_bytes()
            || bytes[54..56] != 56u16.to_le_bytes()
        {
            return Err(Error::Invalid);
        }
        let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
        if count == 0 || count == u16::MAX as usize {
            return Err(Error::Invalid);
        }
        let phoff = extent(bytes, word(bytes, 32), count as u64 * 56)?.start;
        let mut image = Self {
            bytes,
            phoff,
            count,
            fixed: bytes[16..18] == 2u16.to_le_bytes(),
            entry: word(bytes, 24),
            alignment: PAGE,
            minimum: u64::MAX,
            maximum: 0,
            loads: 0,
        };
        let mut executable = false;
        let mut phdr = None;
        let mut stack = false;
        for i in 0..count {
            let s = image.segment(i);
            if s.kind == STACK {
                if stack || s.flags & 1 != 0 {
                    return Err(Error::Unsupported);
                }
                stack = true;
            }
            if s.kind == PHDR && phdr.replace(s).is_some() {
                return Err(Error::Invalid);
            }
            if s.kind != LOAD {
                continue;
            }
            extent(bytes, s.offset, s.file)?;
            if s.file > s.memory
                || s.flags & !7 != 0
                || s.flags & 3 == 3
                || (s.alignment > 1
                    && (!s.alignment.is_power_of_two()
                        || s.address % s.alignment != s.offset % s.alignment))
            {
                return Err(Error::Invalid);
            }
            let end = add(s.address, s.memory)?;
            if end > USER_END {
                return Err(Error::Invalid);
            }
            image.alignment = image.alignment.max(s.alignment);
            if s.memory == 0 {
                continue;
            }
            let low = s.address & !(PAGE - 1);
            let high = align(end, PAGE)?;
            for j in 0..i {
                let other = image.segment(j);
                if other.kind == LOAD
                    && other.memory != 0
                    && low < align(add(other.address, other.memory)?, PAGE)?
                    && (other.address & !(PAGE - 1)) < high
                {
                    return Err(Error::Invalid);
                }
            }
            image.minimum = image.minimum.min(low);
            image.maximum = image.maximum.max(high);
            image.loads += 1;
            executable |= s.flags & 1 != 0 && s.address <= image.entry && image.entry < end;
        }
        if (require_entry && !executable)
            || image.loads == 0
            || (image.fixed && image.minimum < USER_MIN)
        {
            return Err(Error::Invalid);
        }
        if let Some(p) = phdr {
            if p.file != count as u64 * 56
                || p.memory < p.file
                || p.offset != phoff as u64
                || image.header_address(0) != Some(p.address)
            {
                return Err(Error::Invalid);
            }
        }
        image.interpreter()?;
        Ok(image)
    }
    pub(crate) fn segment(self, i: usize) -> Segment {
        let b = &self.bytes[self.phoff + i * 56..self.phoff + (i + 1) * 56];
        Segment {
            kind: u32::from_le_bytes(b[..4].try_into().unwrap()),
            flags: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            offset: word(b, 8),
            address: word(b, 16),
            file: word(b, 32),
            memory: word(b, 40),
            alignment: word(b, 48),
        }
    }
    pub(crate) fn count(self) -> usize {
        self.count
    }
    pub(crate) fn bytes(self, segment: Segment) -> &'a [u8] {
        &self.bytes[segment.offset as usize..(segment.offset + segment.file) as usize]
    }
    pub(crate) fn mapping_range(self, bias: u64) -> Result<(u64, u64), Error> {
        if (self.fixed && bias != 0) || bias % self.alignment != 0 {
            return Err(Error::Invalid);
        }
        let start = add(bias, self.minimum)?;
        let end = add(bias, self.maximum)?;
        if start < USER_MIN || end > USER_END {
            return Err(Error::Invalid);
        }
        Ok((start, end))
    }
    pub fn interpreter(self) -> Result<Option<&'a [u8]>, Error> {
        let mut path = None;
        for i in 0..self.count {
            let s = self.segment(i);
            if s.kind == 3 {
                if path.is_some() || !(2..=4096).contains(&s.file) {
                    return Err(Error::Invalid);
                }
                let text = &self.bytes[extent(self.bytes, s.offset, s.file)?];
                if text.last() != Some(&0) || text[..text.len() - 1].contains(&0) {
                    return Err(Error::Invalid);
                }
                path = Some(&text[..text.len() - 1]);
            }
        }
        Ok(path)
    }
    fn header_address(self, bias: u64) -> Option<u64> {
        let length = self.count as u64 * 56;
        for i in 0..self.count {
            let s = self.segment(i);
            if s.kind == LOAD
                && s.flags & 4 != 0
                && self.phoff as u64 >= s.offset
                && (self.phoff as u64).checked_add(length)? <= s.offset.checked_add(s.file)?
            {
                return bias
                    .checked_add(s.address)?
                    .checked_add(self.phoff as u64 - s.offset);
            }
        }
        None
    }
    fn place(self, desired: u64) -> Result<(u64, u64), Error> {
        let bias = if self.fixed {
            0
        } else {
            align(desired, self.alignment)?
        };
        let end = add(bias, self.maximum)?;
        if add(bias, self.minimum)? < USER_MIN || end > USER_END {
            return Err(Error::Invalid);
        }
        Ok((bias, end))
    }
}
/// Discover PT_INTERP without interpreting dynamic relocations or dependency
/// policy. Static and direct-entry callers continue through their own parser.
pub fn interpreter(bytes: &[u8]) -> Result<Option<&[u8]>, Error> {
    if bytes.len() < 64 || bytes[..7] != [0x7f, b'E', b'L', b'F', 2, 1, 1] {
        return Err(Error::Invalid);
    }
    let phoff = word(bytes, 32);
    let count = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as u64;
    if bytes[54..56] != 56u16.to_le_bytes() || count == 0 {
        return Err(Error::Invalid);
    }
    let table = extent(bytes, phoff, count * 56)?;
    if bytes[table]
        .chunks_exact(56)
        .any(|h| u32::from_le_bytes(h[..4].try_into().unwrap()) == 3)
    {
        Image::parse(bytes)?.interpreter()
    } else {
        Ok(None)
    }
}
pub struct Launch<'a> {
    main: Image<'a>,
    loader: Image<'a>,
    main_bias: u64,
    loader_bias: u64,
    metadata_address: u64,
    metadata_length: u64,
    header_count: u16,
    root_headers_offset: usize,
    length: usize,
}
impl<'a> Launch<'a> {
    pub fn new(main: Image<'a>, loader: Image<'a>, random: [u8; 16]) -> Result<Self, Error> {
        if main.interpreter()?.is_none() || loader.interpreter()?.is_some() {
            return Err(Error::Unsupported);
        }
        let (main_bias, main_end) = main.place(
            0x20000000 + (u64::from_le_bytes(random[..8].try_into().unwrap()) & 0x3fff) * PAGE,
        )?;
        let (loader_bias, loader_end) = loader.place(
            (0x40000000 + (u64::from_le_bytes(random[8..].try_into().unwrap()) & 0x3fff) * PAGE)
                .max(main_end),
        )?;
        for i in 0..main.count {
            let a = main.segment(i);
            if a.kind != LOAD || a.memory == 0 {
                continue;
            }
            for j in 0..loader.count {
                let b = loader.segment(j);
                if b.kind == LOAD
                    && b.memory != 0
                    && (add(main_bias, a.address)? & !(PAGE - 1))
                        < align(add(add(loader_bias, b.address)?, b.memory)?, PAGE)?
                    && (add(loader_bias, b.address)? & !(PAGE - 1))
                        < align(add(add(main_bias, a.address)?, a.memory)?, PAGE)?
                {
                    return Err(Error::Invalid);
                }
            }
        }
        let count = main
            .loads
            .checked_add(loader.loads)
            .and_then(|n| n.checked_add(3))
            .filter(|n| *n < u16::MAX as usize)
            .ok_or(Error::TooLarge)?;
        let root_headers_offset = 64 + count * 56;
        let copy = if main.header_address(main_bias).is_none() {
            main.count * 56
        } else {
            0
        };
        let metadata_length = align((root_headers_offset + copy) as u64, PAGE)?;
        let metadata_address = main_end.max(loader_end);
        if add(metadata_address, metadata_length)? > USER_END {
            return Err(Error::Invalid);
        }
        let mut launch = Self {
            main,
            loader,
            main_bias,
            loader_bias,
            metadata_address,
            metadata_length,
            header_count: count as u16,
            root_headers_offset,
            length: 0,
        };
        let mut cursor = metadata_length;
        launch.each_load(|_, s| {
            cursor = add(align(cursor, PAGE)?, s.address & (PAGE - 1))?;
            cursor = add(cursor, s.file)?;
            Ok(())
        })?;
        launch.length = usize::try_from(cursor).map_err(|_| Error::TooLarge)?;
        Ok(launch)
    }
    fn each_load(
        &self,
        mut emit: impl FnMut(Image<'a>, Segment) -> Result<(), Error>,
    ) -> Result<(), Error> {
        for (image, bias) in [(self.main, self.main_bias), (self.loader, self.loader_bias)] {
            for i in 0..image.count {
                let mut s = image.segment(i);
                if s.kind == LOAD && s.memory != 0 {
                    s.address = add(s.address, bias)?;
                    emit(image, s)?;
                }
            }
        }
        Ok(())
    }
    pub fn length(&self) -> usize {
        self.length
    }
    pub fn executable(&self) -> Executable {
        Executable {
            entry: self.main_bias + self.main.entry,
            program_headers: self
                .main
                .header_address(self.main_bias)
                .unwrap_or(self.metadata_address + self.root_headers_offset as u64),
            program_header_size: 56,
            program_header_count: self.main.count as u64,
            interpreter_base: self.loader_bias,
            load_bias: self.main_bias,
        }
    }
    /// Preserve all original LOAD bytes. The interpreter receives dynamic
    /// records, symbols and relocation tables exactly as captured, unmodified.
    pub fn write(&self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < self.length {
            return Err(Error::ShortOutput);
        }
        output[..self.length].fill(0);
        output[..64].copy_from_slice(&self.main.bytes[..64]);
        output[16..18].copy_from_slice(&2u16.to_le_bytes());
        output[24..32].copy_from_slice(&(self.loader_bias + self.loader.entry).to_le_bytes());
        output[32..40].copy_from_slice(&64u64.to_le_bytes());
        output[40..48].fill(0);
        output[56..58].copy_from_slice(&self.header_count.to_le_bytes());
        output[58..64].fill(0);
        Segment {
            kind: LOAD,
            flags: 4,
            offset: 0,
            address: self.metadata_address,
            file: self.metadata_length,
            memory: self.metadata_length,
            alignment: PAGE,
        }
        .write(output, 64);
        Segment {
            kind: PHDR,
            flags: 4,
            offset: 64,
            address: self.metadata_address + 64,
            file: self.header_count as u64 * 56,
            memory: self.header_count as u64 * 56,
            alignment: 8,
        }
        .write(output, 120);
        Segment {
            kind: STACK,
            flags: 6,
            offset: 0,
            address: 0,
            file: 0,
            memory: 0,
            alignment: 16,
        }
        .write(output, 176);
        if self.main.header_address(self.main_bias).is_none() {
            let start = self.root_headers_offset;
            let source = self.main.phoff;
            let length = self.main.count * 56;
            output[start..start + length]
                .copy_from_slice(&self.main.bytes[source..source + length]);
        }
        let mut cursor = self.metadata_length;
        let mut header = 232;
        self.each_load(|image, mut s| {
            cursor = add(align(cursor, PAGE)?, s.address & (PAGE - 1))?;
            let source = extent(image.bytes, s.offset, s.file)?;
            let at = usize::try_from(cursor).map_err(|_| Error::TooLarge)?;
            output[at..at + source.len()].copy_from_slice(&image.bytes[source]);
            s.offset = cursor;
            s.alignment = PAGE;
            s.write(output, header);
            header += 56;
            cursor = add(cursor, s.file)?;
            Ok(())
        })?;
        Ok(self.length)
    }
}
