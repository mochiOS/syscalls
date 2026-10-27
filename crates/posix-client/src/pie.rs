//! Allocation-free x86-64 static-PIE preparation. Dynamic linking policy lives
//! in user space; this produces an ordinary fixed-address ELF for native exec.
//! Explicit captured object sets can use link_scope for inter-object binding.
//! Standalone exec rejects dependencies, interpreters and resolver execution;
//! acquiring, mapping and initializing a complete object set remains user-space policy.
pub mod link_scope;
mod symbols;

#[derive(Clone, Copy)]
enum Value {
    Relative(u64),
    Absolute(u64),
    Symbol { index: u32, addend: u64 },
}
impl Value {
    fn at(self, bias: u64) -> Result<u64, Error> {
        Ok(match self {
            Self::Relative(value) => bias.wrapping_add(value),
            Self::Absolute(value) => value,
            Self::Symbol { .. } => return Err(Error::Unsupported),
        })
    }
}

const PAGE: u64 = 4096;
const LOAD: u32 = 1;
const DYNAMIC: u32 = 2;
const INTERP: u32 = 3;
const PHDR: u32 = 6;
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

/// User-space search metadata; strings remain borrowed from captured bytes.
#[derive(Default)]
pub struct SearchPaths<'a> {
    pub rpath: Option<&'a [u8]>,
    pub runpath: Option<&'a [u8]>,
    pub no_default_library_path: bool,
}

pub struct Pie<'a> {
    bytes: &'a [u8],
    count: usize,
    entry: u64,
    rela_offset: usize,
    rela_count: usize,
    plt_offset: usize,
    plt_count: usize,
    relr_offset: usize,
    relr_count: usize,
    retained: usize,
    symbols: Option<symbols::Table<'a>>,
    dynamic_segment: Option<Segment>,
    linkable: bool,
    symbolic: bool,
}
impl<'a> Pie<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::parse_mode(bytes, false)
    }
    /// Parse a member of an explicit user-space link scope. Dependencies and
    /// unresolved symbols must be supplied by that scope before writing it.
    pub fn parse_object(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::parse_mode(bytes, true)
    }
    fn parse_mode(bytes: &'a [u8], linkable: bool) -> Result<Self, Error> {
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
            plt_offset: 0,
            plt_count: 0,
            relr_offset: 0,
            relr_count: 0,
            retained: 0,
            symbols: None,
            dynamic_segment: None,
            linkable,
            symbolic: false,
        };
        let mut dynamic = None;
        let mut executable = false;
        for i in 0..count {
            let s = result.segment(i)?;
            if s.kind == INTERP {
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
        if (!executable && !linkable)
            || result
                .retained
                .checked_add(2)
                .is_none_or(|n| n > u16::MAX as usize)
        {
            return Err(Error::Invalid);
        }
        if let Some(d) = dynamic {
            result.dynamic_segment = Some(d);
            result.dynamic(d)?;
        }
        result.dependencies(|_| Ok(()))?;
        result.search_paths()?;
        // Reuse the runtime's TLS validation, reading the source PHDR bytes.
        // Only the initialized template must be file-backed; .tbss may extend
        // beyond LOAD memory. Symbol-bearing TLS relocations remain rejected.
        crate::static_tls::template(
            usize::try_from(u64_at(bytes, 32)?).map_err(|_| Error::Overflow)?,
            56,
            count,
            0,
            |address, output| {
                let range = extent(bytes, address as u64, output.len() as u64)?;
                output.copy_from_slice(&bytes[range]);
                Ok(())
            },
        )
        .map_err(|error| match error {
            crate::static_tls::Error::InvalidImage => Error::Invalid,
            crate::static_tls::Error::Read(error) => error,
        })?;
        let mut seen = 0usize;
        let mut highest_end = 0;
        result.relocations(|target, _| {
            let end = add(target, 8)?;
            if !(0..count).any(|n| result.segment(n).is_ok_and(|s| s.contains(target, 8))) {
                return Err(Error::Invalid);
            }
            // Linkers normally emit sorted targets. Validate these in one pass;
            // unsorted tables are allowed but must still have disjoint writes.
            if target < highest_end {
                let mut index = 0;
                result.relocations(|old, _| {
                    if index < seen && target < add(old, 8)? && old < end {
                        return Err(Error::Invalid);
                    }
                    index += 1;
                    Ok(())
                })?;
            }
            highest_end = highest_end.max(end);
            seen += 1;
            Ok(())
        })?;
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
        let mut plt = None;
        let mut plt_size = None;
        let mut plt_kind = None;
        let mut relr = None;
        let mut relr_size = None;
        let mut relr_entry = None;
        let mut symbol_tags = [None; 6];
        let mut versioned = false;
        let mut terminated = false;
        for o in extent(self.bytes, d.offset, d.file)?.step_by(16) {
            let tag = u64_at(self.bytes, o)?;
            let value = u64_at(self.bytes, o + 8)?;
            if tag == 0 {
                terminated = true;
                break;
            }
            let symbol_index = match tag {
                4 => Some(0),
                5 => Some(1),
                6 => Some(2),
                10 => Some(3),
                11 => Some(4),
                0x6ffffef5 => Some(5),
                _ => None,
            };
            if let Some(index) = symbol_index {
                if symbol_tags[index].replace(value).is_some() {
                    return Err(Error::Invalid);
                }
            }
            if matches!(tag, 0x6ffffff0 | 0x6ffffffc..=0x6fffffff) {
                versioned = true;
            }
            match tag {
                // Dependency loading and external audit/filter scopes require
                // an object graph, lifetime management and authority checks.
                1 if !self.linkable => return Err(Error::Unsupported),
                0x6ffffefb | 0x6ffffefc | 0x7ffffffd | 0x7fffffff => {
                    return Err(Error::Unsupported);
                }
                16 => self.symbolic = true,
                30 => self.symbolic |= value & 2 != 0,
                2 => {
                    if plt_size.replace(value).is_some() {
                        return Err(Error::Invalid);
                    }
                }
                20 => {
                    if plt_kind.replace(value).is_some() {
                        return Err(Error::Invalid);
                    }
                }
                23 => {
                    if plt.replace(value).is_some() {
                        return Err(Error::Invalid);
                    }
                }
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
                35 => {
                    if relr_size.replace(value).is_some() {
                        return Err(Error::Invalid);
                    }
                }
                36 => {
                    if relr.replace(value).is_some() {
                        return Err(Error::Invalid);
                    }
                }
                37 => {
                    if relr_entry.replace(value).is_some() {
                        return Err(Error::Invalid);
                    }
                }
                // DT_REL/RELSZ.
                17 | 18 if value != 0 => return Err(Error::Unsupported),
                _ => {}
            }
        }
        if !terminated {
            return Err(Error::Invalid);
        }
        if symbol_tags.iter().any(Option::is_some) {
            self.symbols = Some(symbols::Table::parse(
                symbol_tags,
                versioned,
                |address, length| Ok(&self.bytes[self.file_range(address, length)?]),
            )?);
        }
        let size = size.unwrap_or(0);
        if size != 0 {
            if size % 24 != 0 || entry != Some(24) {
                return Err(Error::Invalid);
            }
            let range = self.file_range(rela.ok_or(Error::Invalid)?, size)?;
            self.rela_offset = range.start;
            self.rela_count = range.len() / 24;
        }
        if plt.is_some() || plt_size.is_some() || plt_kind.is_some() {
            let size = plt_size.ok_or(Error::Invalid)?;
            if plt_kind != Some(7) {
                return Err(Error::Unsupported);
            }
            if size % 24 != 0 {
                return Err(Error::Invalid);
            }
            let range = self.file_range(plt.ok_or(Error::Invalid)?, size)?;
            self.plt_offset = range.start;
            self.plt_count = range.len() / 24;
        }
        if relr.is_some() || relr_size.is_some() || relr_entry.is_some() {
            let size = relr_size.ok_or(Error::Invalid)?;
            if relr_entry != Some(8) || size % 8 != 0 {
                return Err(Error::Invalid);
            }
            let range = self.file_range(relr.ok_or(Error::Invalid)?, size)?;
            self.relr_offset = range.start;
            self.relr_count = range.len() / 8;
        }
        Ok(())
    }
    /// Read an implicit addend from the unmodified LOAD image, including a word
    /// that straddles file bytes and zero-fill. Never read it from prior fixups.
    fn relative_word(&self, target: u64) -> Result<u64, Error> {
        for i in 0..self.count {
            let s = self.segment(i)?;
            if s.contains(target, 8) {
                let within = target - s.address;
                let length = s.file.saturating_sub(within).min(8);
                let mut word = [0; 8];
                if length != 0 {
                    let range = extent(self.bytes, add(s.offset, within)?, length)?;
                    word[..length as usize].copy_from_slice(&self.bytes[range]);
                }
                return Ok(u64::from_le_bytes(word));
            }
        }
        Err(Error::Invalid)
    }
    /// gABI RELR bitmaps cover the next 63 words, including zero bits. Process
    /// RELR before RELA; all reads use the immutable source so tables may reside
    /// in a LOAD that also contains relocation targets.
    fn relocations(
        &self,
        mut apply: impl FnMut(u64, Value) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut cursor = None;
        for index in 0..self.relr_count {
            let word = u64_at(self.bytes, self.relr_offset + index * 8)?;
            if word & 1 == 0 {
                apply(word, Value::Relative(self.relative_word(word)?))?;
                cursor = Some(add(word, 8)?);
            } else {
                let base = cursor.ok_or(Error::Invalid)?;
                let end = add(base, 63 * 8)?;
                for bit in 1..64 {
                    if word & (1u64 << bit) != 0 {
                        let target = add(base, (bit - 1) * 8)?;
                        apply(target, Value::Relative(self.relative_word(target)?))?;
                    }
                }
                cursor = Some(end);
            }
        }
        for (offset, count) in [
            (self.rela_offset, self.rela_count),
            (self.plt_offset, self.plt_count),
        ] {
            for index in 0..count {
                if let (target, Some(value)) = self.relocation(offset + index * 24)? {
                    apply(target, value)?;
                }
            }
        }
        Ok(())
    }
    /// Relative and single-image symbol bindings. Symbol version scopes,
    /// dependencies, TLS and IFUNC are not approximated by local lookup.
    fn relocation(&self, o: usize) -> Result<(u64, Option<Value>), Error> {
        let target = u64_at(self.bytes, o)?;
        let info = u64_at(self.bytes, o + 8)?;
        let kind = info as u32;
        let symbol = (info >> 32) as u32;
        let addend = u64_at(self.bytes, o + 16)?;
        let value = match kind {
            0 => return Ok((target, None)),
            8 if symbol == 0 => Value::Relative(addend),
            1 | 6 | 7 => {
                let table = self.symbols.as_ref().ok_or(Error::Unsupported)?;
                let reference = table.entry(symbol)?;
                if let Some(definition) = reference.definition {
                    self.definition_value(definition)?;
                }
                if !self.linkable {
                    table.definition(symbol)?;
                }
                Value::Symbol {
                    index: symbol,
                    addend: if kind == 1 { addend } else { 0 },
                }
            }
            _ => return Err(Error::Unsupported),
        };
        Ok((target, Some(value)))
    }
    fn definition_value(&self, definition: symbols::Definition) -> Result<Value, Error> {
        match definition {
            symbols::Definition::Absolute(value) => Ok(Value::Absolute(value)),
            symbols::Definition::Image { value, size } => {
                if !(0..self.count).any(|i| self.segment(i).is_ok_and(|s| s.contains(value, size)))
                {
                    return Err(Error::Invalid);
                }
                Ok(Value::Relative(value))
            }
        }
    }
    /// Enumerate DT_NEEDED names in source order. This never opens a pathname.
    pub fn dependencies(
        &self,
        mut visit: impl FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if let Some(dynamic) = self.dynamic_segment {
            for offset in extent(self.bytes, dynamic.offset, dynamic.file)?.step_by(16) {
                match u64_at(self.bytes, offset)? {
                    0 => break,
                    1 => {
                        let table = self.symbols.as_ref().ok_or(Error::Invalid)?;
                        let name = table.string(u64_at(self.bytes, offset + 8)?)?;
                        if name.is_empty() {
                            return Err(Error::Invalid);
                        }
                        visit(name)?;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
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
                    load_bias: bias,
                });
            }
        }
        Err(Error::Unsupported)
    }

    /// Conservative placement after a caller-selected address, including the
    /// native metadata mapping. Returns (load bias, first free page).
    pub fn placement(&self, minimum: u64) -> Result<(u64, u64), Error> {
        let mut start = u64::MAX;
        let mut end = 0;
        for index in 0..self.count {
            let segment = self.segment(index)?;
            if segment.kind == LOAD && segment.memory != 0 {
                start = start.min(segment.address & !(PAGE - 1));
                end = end.max(page(add(segment.address, segment.memory)?)?);
            }
        }
        if start == u64::MAX {
            return Err(Error::Invalid);
        }
        let required = add(minimum, self.metadata_bytes()?)?.saturating_sub(start);
        let alignment = self.alignment();
        let bias = add(required, alignment - 1)? & !(alignment - 1);
        Ok((bias, add(end, bias)?))
    }
    pub fn search_paths(&self) -> Result<SearchPaths<'a>, Error> {
        let mut paths = SearchPaths::default();
        if let Some(dynamic) = self.dynamic_segment {
            for offset in extent(self.bytes, dynamic.offset, dynamic.file)?.step_by(16) {
                let tag = u64_at(self.bytes, offset)?;
                if tag == 0 {
                    break;
                }
                let value = u64_at(self.bytes, offset + 8)?;
                match tag {
                    15 | 29 => {
                        let text = self.symbols.as_ref().ok_or(Error::Invalid)?.string(value)?;
                        let destination = if tag == 15 {
                            &mut paths.rpath
                        } else {
                            &mut paths.runpath
                        };
                        if destination.replace(text).is_some() {
                            return Err(Error::Invalid);
                        }
                    }
                    0x6ffffffb => paths.no_default_library_path = value & 0x800 != 0,
                    _ => {}
                }
            }
        }
        Ok(paths)
    }
    /// A direct-entry scope currently has no constructor runner. Do not
    /// silently ignore these requirements while wiring exec.
    pub fn validate_direct_scope_startup(&self) -> Result<(), Error> {
        if let Some(dynamic) = self.dynamic_segment {
            for offset in extent(self.bytes, dynamic.offset, dynamic.file)?.step_by(16) {
                let tag = u64_at(self.bytes, offset)?;
                if tag == 0 {
                    break;
                }
                if matches!(tag, 12 | 13 | 25..=28 | 32 | 33)
                    && u64_at(self.bytes, offset + 8)? != 0
                {
                    return Err(Error::Unsupported);
                }
            }
        }
        Ok(())
    }
    pub fn alignment(&self) -> u64 {
        (0..self.count)
            .filter_map(|i| self.segment(i).ok())
            .filter(|s| s.kind == LOAD)
            .fold(PAGE, |a, s| a.max(s.alignment))
    }
    fn materialized(&self, s: Segment) -> Result<u64, Error> {
        let mut length = s.file;
        self.relocations(|target, _| {
            if s.contains(target, 8) {
                length = length.max(add(target - s.address, 8)?);
            }
            Ok(())
        })?;
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
        self.dependencies(|_| Err(Error::Unsupported))?;
        self.write_resolved(bias, output, |index| {
            let definition = self
                .symbols
                .as_ref()
                .ok_or(Error::Unsupported)?
                .definition(index)?;
            self.definition_value(definition)?.at(bias)
        })
    }
    fn write_resolved(
        &self,
        bias: u64,
        output: &mut [u8],
        mut resolve: impl FnMut(u32) -> Result<u64, Error>,
    ) -> Result<usize, Error> {
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
        for j in 0..self.count {
            let s = self.segment(j)?;
            if s.kind != LOAD {
                continue;
            }
            // Compute layout once per LOAD, rather than rescanning all fixups
            // for every individual word in a dense RELR bitmap.
            let destination = self.load_offset(j)?;
            self.relocations(|target, value| {
                if s.contains(target, 8) {
                    // ELF64 B + A is modular data, not an authorized range.
                    let value = match value {
                        Value::Symbol { index, addend } => resolve(index)?.wrapping_add(addend),
                        value => value.at(bias)?,
                    };
                    let offset = add(destination, target - s.address)? as usize;
                    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
                }
                Ok(())
            })?;
        }
        Ok(length)
    }
}
