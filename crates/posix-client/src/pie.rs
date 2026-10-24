//! Allocation-free x86-64 static-PIE preparation. Dynamic linking policy lives
//! in user space; this produces an ordinary fixed-address ELF for native exec.
//! Symbol lookup, interpreters, TLS and resolver execution require a runtime
//! linker and are deliberately reported as unsupported, never silently ignored.
const PAGE: u64 = 4096;
const LOAD: u32 = 1;
const DYNAMIC: u32 = 2;
const INTERP: u32 = 3;
const PHDR: u32 = 6;
const TLS: u32 = 7;
const EH_FRAME: u32 = 0x6474e550;
const GNU_STACK: u32 = 0x6474e551;
const RELRO: u32 = 0x6474e552;
const USER_MIN: u64 = 0x0040_0000;
const USER_END: u64 = 0x0000_8000_0000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Unsupported,
    Overflow,
    BufferTooSmall,
}

fn u16_at(b: &[u8], o: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(
        b.get(o..o + 2).ok_or(Error::Invalid)?.try_into().unwrap(),
    ))
}
fn u32_at(b: &[u8], o: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        b.get(o..o + 4).ok_or(Error::Invalid)?.try_into().unwrap(),
    ))
}
fn u64_at(b: &[u8], o: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(
        b.get(o..o + 8).ok_or(Error::Invalid)?.try_into().unwrap(),
    ))
}
fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b).ok_or(Error::Overflow)
}
fn page(a: u64) -> Result<u64, Error> {
    Ok(add(a, PAGE - 1)? & !(PAGE - 1))
}
fn extent(bytes: &[u8], offset: u64, length: u64) -> Result<core::ops::Range<usize>, Error> {
    let end = add(offset, length)?;
    let start = usize::try_from(offset).map_err(|_| Error::Overflow)?;
    let end = usize::try_from(end).map_err(|_| Error::Overflow)?;
    if end > bytes.len() {
        return Err(Error::Invalid);
    }
    Ok(start..end)
}

#[derive(Clone, Copy)]
struct Segment {
    kind: u32,
    flags: u32,
    offset: u64,
    address: u64,
    file: u64,
    memory: u64,
    alignment: u64,
}
impl Segment {
    fn retained(self) -> bool {
        matches!(self.kind, LOAD | EH_FRAME | GNU_STACK | RELRO)
    }
    fn contains(self, address: u64, length: u64) -> bool {
        self.kind == LOAD
            && address >= self.address
            && address
                .checked_add(length)
                .zip(self.address.checked_add(self.memory))
                .is_some_and(|(a, b)| a <= b)
    }
    fn write(self, output: &mut [u8], offset: usize) {
        output[offset..offset + 4].copy_from_slice(&self.kind.to_le_bytes());
        output[offset + 4..offset + 8].copy_from_slice(&self.flags.to_le_bytes());
        for (i, value) in [
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
            output[offset + 8 + i * 8..offset + 16 + i * 8].copy_from_slice(&value.to_le_bytes());
        }
    }
}

pub struct Pie<'a> {
    bytes: &'a [u8],
    count: usize,
    entry: u64,
    rela_offset: usize,
    rela_count: usize,
    retained: usize,
}
impl<'a> Pie<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < 64
            || bytes[..7] != [0x7f, b'E', b'L', b'F', 2, 1, 1]
            || u16_at(bytes, 16)? != 3
            || u16_at(bytes, 18)? != 62
            || u32_at(bytes, 20)? != 1
            || u16_at(bytes, 52)? != 64
            || u16_at(bytes, 54)? != 56
        {
            return Err(Error::Invalid);
        }
        let count = usize::from(u16_at(bytes, 56)?);
        if count == 0 {
            return Err(Error::Invalid);
        }
        extent(bytes, u64_at(bytes, 32)?, (count as u64) * 56)?;
        let mut result = Self {
            bytes,
            count,
            entry: u64_at(bytes, 24)?,
            rela_offset: 0,
            rela_count: 0,
            retained: 0,
        };
        let mut dynamic = None;
        let mut executable = false;
        for i in 0..count {
            let s = result.segment(i)?;
            if matches!(s.kind, INTERP | TLS) {
                return Err(Error::Unsupported);
            }
            if s.kind == GNU_STACK && s.flags & 1 != 0 {
                return Err(Error::Unsupported);
            }
            if s.retained() {
                result.retained += 1;
            }
            if matches!(s.kind, EH_FRAME | RELRO)
                && s.file != 0
                && result.file_range(s.address, s.file)? != extent(bytes, s.offset, s.file)?
            {
                return Err(Error::Invalid);
            }
            if s.kind == DYNAMIC {
                if dynamic.replace(s).is_some() {
                    return Err(Error::Invalid);
                }
            }
            if s.kind != LOAD {
                continue;
            }
            extent(bytes, s.offset, s.file)?;
            if s.file > s.memory
                || s.flags & !7 != 0
                || s.flags & 3 == 3
                || s.alignment > 1
                    && (!s.alignment.is_power_of_two()
                        || s.address % s.alignment != s.offset % s.alignment)
            {
                return Err(Error::Invalid);
            }
            let end = add(s.address, s.memory)?;
            if s.flags & 1 != 0 && s.address <= result.entry && result.entry < end {
                executable = true;
            }
            if s.memory != 0 {
                for j in 0..i {
                    let other = result.segment(j)?;
                    if other.kind == LOAD
                        && other.memory != 0
                        && (s.address & !(PAGE - 1)) < page(add(other.address, other.memory)?)?
                        && (other.address & !(PAGE - 1)) < page(end)?
                    {
                        return Err(Error::Invalid);
                    }
                }
            }
        }
        if !executable
            || result
                .retained
                .checked_add(2)
                .is_none_or(|n| n > u16::MAX as usize)
        {
            return Err(Error::Invalid);
        }
        if let Some(d) = dynamic {
            result.dynamic(d)?;
        }
        for i in 0..result.rela_count {
            let (target, value) = result.relocation(i)?;
            if value.is_none() {
                continue;
            }
            if !(0..count).any(|n| result.segment(n).is_ok_and(|s| s.contains(target, 8))) {
                return Err(Error::Invalid);
            }
            for j in 0..i {
                let (old, value) = result.relocation(j)?;
                if value.is_some() && target < add(old, 8)? && old < add(target, 8)? {
                    return Err(Error::Invalid);
                }
            }
        }
        Ok(result)
    }
    fn segment(&self, index: usize) -> Result<Segment, Error> {
        let offset = usize::try_from(u64_at(self.bytes, 32)?).map_err(|_| Error::Overflow)?;
        let o = offset
            .checked_add(index.checked_mul(56).ok_or(Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        Ok(Segment {
            kind: u32_at(self.bytes, o)?,
            flags: u32_at(self.bytes, o + 4)?,
            offset: u64_at(self.bytes, o + 8)?,
            address: u64_at(self.bytes, o + 16)?,
            file: u64_at(self.bytes, o + 32)?,
            memory: u64_at(self.bytes, o + 40)?,
            alignment: u64_at(self.bytes, o + 48)?,
        })
    }
    fn file_range(&self, address: u64, length: u64) -> Result<core::ops::Range<usize>, Error> {
        for i in 0..self.count {
            let s = self.segment(i)?;
            if s.kind == LOAD
                && address >= s.address
                && add(address, length)? <= add(s.address, s.file)?
            {
                return extent(self.bytes, add(s.offset, address - s.address)?, length);
            }
        }
        Err(Error::Invalid)
    }
    fn dynamic(&mut self, d: Segment) -> Result<(), Error> {
        if d.file == 0
            || d.file % 16 != 0
            || self.file_range(d.address, d.file)? != extent(self.bytes, d.offset, d.file)?
        {
            return Err(Error::Invalid);
        }
        let mut rela = None;
        let mut size = None;
        let mut entry = None;
        let mut terminated = false;
        for o in extent(self.bytes, d.offset, d.file)?.step_by(16) {
            let tag = u64_at(self.bytes, o)?;
            let value = u64_at(self.bytes, o + 8)?;
            if tag == 0 {
                terminated = true;
                break;
            }
            match tag {
                1 => return Err(Error::Unsupported), // DT_NEEDED requires symbol scope/lifetime management.
                7 => {
                    if rela.replace(value).is_some() {
                        return Err(Error::Invalid);
                    }
                }
                8 => {
                    if size.replace(value).is_some() {
                        return Err(Error::Invalid);
                    }
                }
                9 => {
                    if entry.replace(value).is_some() {
                        return Err(Error::Invalid);
                    }
                }
                // DT_PLTRELSZ, DT_REL/RELSZ, DT_JMPREL, DT_RELR/RELRSZ.
                2 | 17 | 18 | 23 | 35 | 36 if value != 0 => return Err(Error::Unsupported),
                _ => {}
            }
        }
        if !terminated {
            return Err(Error::Invalid);
        }
        let size = size.unwrap_or(0);
        if size == 0 {
            return Ok(());
        }
        if size % 24 != 0 || entry != Some(24) {
            return Err(Error::Invalid);
        }
        let range = self.file_range(rela.ok_or(Error::Invalid)?, size)?;
        self.rela_offset = range.start;
        self.rela_count = range.len() / 24;
        Ok(())
    }
    /// (target, signed relative addend); NONE performs no write.
    fn relocation(&self, index: usize) -> Result<(u64, Option<i64>), Error> {
        let o = self.rela_offset + index * 24;
        let target = u64_at(self.bytes, o)?;
        let info = u64_at(self.bytes, o + 8)?;
        match info {
            0 => Ok((target, None)),
            8 => Ok((target, Some(u64_at(self.bytes, o + 16)? as i64))),
            _ => Err(Error::Unsupported),
        }
    }
    /// Retain the source program's PHDR view, not the native wrapper's table.
    /// A runtime linker/self-relocator interprets these with the program bias.
    pub fn executable(&self, bias: u64) -> Result<crate::process_image::Executable, Error> {
        let offset = u64_at(self.bytes, 32)?;
        let length = (self.count as u64) * 56;
        for i in 0..self.count {
            let s = self.segment(i)?;
            if s.kind == LOAD
                && offset >= s.offset
                && add(offset, length)? <= add(s.offset, s.file)?
            {
                return Ok(crate::process_image::Executable {
                    entry: add(self.entry, bias)?,
                    program_headers: add(add(s.address, offset - s.offset)?, bias)?,
                    program_header_size: 56,
                    program_header_count: self.count as u64,
                    interpreter_base: 0,
                });
            }
        }
        Err(Error::Unsupported)
    }

    pub fn alignment(&self) -> u64 {
        (0..self.count)
            .filter_map(|i| self.segment(i).ok())
            .filter(|s| s.kind == LOAD)
            .fold(PAGE, |a, s| a.max(s.alignment))
    }
    fn materialized(&self, s: Segment) -> Result<u64, Error> {
        let mut length = s.file;
        for i in 0..self.rela_count {
            let (target, value) = self.relocation(i)?;
            if value.is_some() && s.contains(target, 8) {
                length = length.max(add(target - s.address, 8)?);
            }
        }
        Ok(length)
    }
    fn metadata_bytes(&self) -> Result<u64, Error> {
        page(64 + (self.retained as u64 + 2) * 56)
    }
    fn load_offset(&self, index: usize) -> Result<u64, Error> {
        let mut offset = self.metadata_bytes()?;
        for i in 0..=index {
            let s = self.segment(i)?;
            if s.kind != LOAD {
                continue;
            }
            offset = add(page(offset)?, s.address & (PAGE - 1))?;
            if i == index {
                return Ok(offset);
            }
            offset = add(offset, self.materialized(s)?)?;
        }
        Err(Error::Invalid)
    }
    pub fn output_length(&self) -> Result<usize, Error> {
        let mut length = self.metadata_bytes()?;
        for i in 0..self.count {
            let s = self.segment(i)?;
            if s.kind == LOAD {
                length = add(self.load_offset(i)?, self.materialized(s)?)?;
            }
        }
        usize::try_from(length).map_err(|_| Error::Overflow)
    }
    /// Constructs a fixed-address ELF in caller-owned storage. A synthetic
    /// read-only LOAD owns its program headers, independent of source offsets.
    pub fn write(&self, bias: u64, output: &mut [u8]) -> Result<usize, Error> {
        if bias % self.alignment() != 0 {
            return Err(Error::Invalid);
        }
        let length = self.output_length()?;
        if output.len() < length {
            return Err(Error::BufferTooSmall);
        }
        let minimum = (0..self.count)
            .filter_map(|i| self.segment(i).ok())
            .filter(|s| s.kind == LOAD && s.memory != 0)
            .map(|s| s.address & !(PAGE - 1))
            .min()
            .ok_or(Error::Invalid)?;
        let metadata = self.metadata_bytes()?;
        let base = add(bias, minimum)?
            .checked_sub(metadata)
            .filter(|a| *a >= USER_MIN)
            .ok_or(Error::Invalid)?;
        let entry = add(self.entry, bias)?;
        for i in 0..self.count {
            let s = self.segment(i)?;
            if s.kind == LOAD && add(add(s.address, bias)?, s.memory)? > USER_END {
                return Err(Error::Invalid);
            }
        }
        output[..length].fill(0);
        output[..64].copy_from_slice(&self.bytes[..64]);
        output[16..18].copy_from_slice(&2u16.to_le_bytes());
        output[24..32].copy_from_slice(&entry.to_le_bytes());
        output[32..40].copy_from_slice(&64u64.to_le_bytes());
        output[40..48].fill(0); // source section headers do not describe this image.
        output[56..58].copy_from_slice(&((self.retained + 2) as u16).to_le_bytes());
        output[58..64].fill(0);
        Segment {
            kind: LOAD,
            flags: 4,
            offset: 0,
            address: base,
            file: metadata,
            memory: metadata,
            alignment: PAGE,
        }
        .write(output, 64);
        Segment {
            kind: PHDR,
            flags: 4,
            offset: 64,
            address: base + 64,
            file: (self.retained as u64 + 2) * 56,
            memory: (self.retained as u64 + 2) * 56,
            alignment: 8,
        }
        .write(output, 120);
        let mut next = 176;
        for i in 0..self.count {
            let mut s = self.segment(i)?;
            if !s.retained() {
                continue;
            }
            if s.kind == LOAD {
                let offset = self.load_offset(i)?;
                let source = extent(self.bytes, s.offset, s.file)?;
                output[offset as usize..offset as usize + source.len()]
                    .copy_from_slice(&self.bytes[source]);
                s.offset = offset;
                s.file = self.materialized(s)?;
                s.alignment = PAGE;
            } else if s.kind != GNU_STACK && s.file != 0 {
                let mut translated = None;
                for j in 0..self.count {
                    let load = self.segment(j)?;
                    if load.kind == LOAD
                        && s.address >= load.address
                        && add(s.address, s.file)? <= add(load.address, load.file)?
                    {
                        translated = Some(add(self.load_offset(j)?, s.address - load.address)?);
                        break;
                    }
                }
                s.offset = translated.ok_or(Error::Invalid)?;
            }
            if s.kind != GNU_STACK {
                s.address = add(s.address, bias)?;
            }
            s.write(output, next);
            next += 56;
        }
        for i in 0..self.rela_count {
            let (target, Some(addend)) = self.relocation(i)? else {
                continue;
            };
            // ELF64 relocation fields hold B + A modulo 2^64. This is
            // data, not a range used to authorize or map an address.
            let value = bias.wrapping_add(addend as u64);
            for j in 0..self.count {
                let s = self.segment(j)?;
                if s.contains(target, 8) {
                    let offset = add(self.load_offset(j)?, target - s.address)? as usize;
                    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                    break;
                }
            }
        }
        Ok(length)
    }
}
