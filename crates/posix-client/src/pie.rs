//! Allocation-free x86-64 ELF preparation. Dynamic linking policy lives
//! in user space; this produces an ordinary fixed-address ELF for native exec.
//! Explicit captured object sets can use link_scope for inter-object binding.
//! Standalone exec rejects dependencies, interpreters and resolver execution;
//! acquiring, mapping and initializing a complete object set remains user-space policy.
mod copy;
mod lifecycle;
pub mod link_scope;
mod symbols;

#[derive(Clone, Copy)]
enum Value {
    Relative(u64),
    Absolute(u64),
    Indirect(u64),
    Symbol { index: u32, addend: u64 },
    Size { index: u32, addend: u64, width: u8 },
    Tls { index: u32, kind: u32, addend: u64 },
    Copy { index: u32, size: u64 },
}
impl Value {
    fn width(self) -> u64 {
        match self {
            Self::Copy { size, .. } => size,
            Self::Tls { kind: 36, .. } => 16,
            Self::Size { width, .. } => u64::from(width),
            _ => 8,
        }
    }
    fn at(self, bias: u64) -> Result<u64, Error> {
        Ok(match self {
            Self::Relative(value) => bias.wrapping_add(value),
            Self::Absolute(value) => value,
            Self::Indirect(_)
            | Self::Symbol { .. }
            | Self::Size { .. }
            | Self::Tls { .. }
            | Self::Copy { .. } => {
                return Err(Error::Unsupported);
            }
        })
    }
    fn encode(
        self,
        bias: u64,
        resolve: &mut impl FnMut(u32, u32) -> Result<u64, Error>,
        descriptor: &mut impl FnMut(u32, u64) -> Result<(u64, u64), Error>,
    ) -> Result<([u8; 16], usize), Error> {
        let mut bytes = [0; 16];
        let value = match self {
            Self::Copy { .. } => return Err(Error::Unsupported),
            Self::Tls {
                index,
                kind: 36,
                addend,
            } => {
                let (function, argument) = descriptor(index, addend)?;
                bytes[..8].copy_from_slice(&function.to_le_bytes());
                bytes[8..].copy_from_slice(&argument.to_le_bytes());
                return Ok((bytes, 16));
            }
            Self::Symbol { index, addend } => resolve(index, 0)?.wrapping_add(addend),
            Self::Size {
                index,
                addend,
                width,
            } => {
                let value = resolve(index, if width == 4 { 32 } else { 33 })?.wrapping_add(addend);
                if width == 4 {
                    let value = u32::try_from(value).map_err(|_| Error::Overflow)?;
                    bytes[..4].copy_from_slice(&value.to_le_bytes());
                    return Ok((bytes, 4));
                }
                value
            }
            Self::Tls {
                index,
                kind,
                addend,
            } => resolve(index, kind)?.wrapping_add(addend),
            value => value.at(bias)?,
        };
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        Ok((bytes, 8))
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
    lifecycle: lifecycle::Metadata,
    fixed: bool,
}
impl<'a> Pie<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::parse_mode(bytes, false)
    }
    /// Parse a member of an explicit user-space link scope. Dependencies and
    /// unresolved symbols must be supplied by that scope before writing it.
    /// ET_EXEC is permitted only as the fixed root, as enforced by Scope.
    pub fn parse_object(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::parse_mode(bytes, true)
    }
    fn parse_mode(bytes: &'a [u8], linkable: bool) -> Result<Self, Error> {
        if bytes.len() < 64
            || bytes[..7] != [0x7f, b'E', b'L', b'F', 2, 1, 1]
            || !(u16_at(bytes, 16)? == 3 || (linkable && u16_at(bytes, 16)? == 2))
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
            lifecycle: lifecycle::Metadata::default(),
            fixed: u16_at(bytes, 16)? == 2,
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
        result.lifecycle = lifecycle::Metadata::parse(&result)?;
        // Reuse the runtime's TLS validation, reading the source PHDR bytes.
        // Only the initialized template must be file-backed; .tbss may extend
        // beyond LOAD memory. TLS relocations require an explicit link scope.
        result.tls_template(0)?;
        let mut seen = 0usize;
        let mut highest_end = 0;
        result.relocations(|target, value| {
            let end = add(target, value.width())?;
            if !(0..count).any(|n| {
                result
                    .segment(n)
                    .is_ok_and(|s| s.contains(target, value.width()))
            }) {
                return Err(Error::Invalid);
            }
            if value.width() == 0 {
                seen += 1;
                return Ok(());
            }
            // Linkers normally emit sorted targets. Validate these in one pass;
            // unsorted tables are allowed but must still have disjoint writes.
            if target < highest_end {
                let mut index = 0;
                result.relocations(|old, value| {
                    if index < seen
                        && value.width() != 0
                        && target < add(old, value.width())?
                        && old < end
                    {
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
        if let Some(table) = &result.symbols {
            table.validate_imported_definitions(|address, size| {
                let mut covered = false;
                result.relocations(|target, value| {
                    if let Value::Copy { size: length, .. } = value {
                        covered |= address >= target && add(address, size)? <= add(target, length)?;
                    }
                    Ok(())
                })?;
                Ok(covered)
            })?;
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
        let mut plt = None;
        let mut plt_size = None;
        let mut plt_kind = None;
        let mut relr = None;
        let mut relr_size = None;
        let mut relr_entry = None;
        let mut symbol_tags = [None; 6];
        let mut version_tags = [None; 5];
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
            let version_index = match tag {
                0x6ffffff0 => Some(0),
                0x6ffffffc..=0x6fffffff => Some((tag - 0x6ffffffc) as usize + 1),
                _ => None,
            };
            if let Some(index) = version_index {
                if version_tags[index].replace(value).is_some() {
                    return Err(Error::Invalid);
                }
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
        if symbol_tags.iter().any(Option::is_some) {
            let mut required_symbols = 1;
            // Validate the complete RELA/PLT extents before deriving a symbol
            // prefix. RELR has no symbol indices; R_NONE addresses no symbol.
            for (offset, count) in [
                (self.rela_offset, self.rela_count),
                (self.plt_offset, self.plt_count),
            ] {
                for index in 0..count {
                    let info = u64_at(self.bytes, offset + index * 24 + 8)?;
                    if info as u32 != 0 {
                        required_symbols = required_symbols.max((info >> 32) + 1);
                    }
                }
            }
            self.symbols = Some(symbols::Table::parse(
                symbol_tags,
                version_tags,
                required_symbols,
                |address, length| Ok(&self.bytes[self.file_range(address, length)?]),
            )?);
            if !self.linkable {
                self.symbols
                    .as_ref()
                    .ok_or(Error::Invalid)?
                    .requirements(|_, _, _, _| Err(Error::Unsupported))?;
            }
        } else if version_tags.iter().any(Option::is_some) {
            return Err(Error::Invalid);
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
    /// TLS and deferred resolver records require an explicit scope. Parsing
    /// never calls a resolver, including a locally defined IFUNC.
    fn relocation(&self, o: usize) -> Result<(u64, Option<Value>), Error> {
        let target = u64_at(self.bytes, o)?;
        let info = u64_at(self.bytes, o + 8)?;
        let kind = info as u32;
        let symbol = (info >> 32) as u32;
        let addend = u64_at(self.bytes, o + 16)?;
        let value = match kind {
            0 => return Ok((target, None)),
            8 if symbol == 0 => Value::Relative(addend),
            37 if symbol == 0 && self.linkable => {
                self.resolver_source(addend, 0)?;
                Value::Indirect(addend)
            }
            32 | 33 => {
                let reference = self.symbols.as_ref().ok_or(Error::Invalid)?.entry(symbol)?;
                if let Some(definition) = reference.definition {
                    self.definition_size(definition, reference.size)?;
                } else if !self.linkable && reference.binding != 2 {
                    return Err(Error::Unsupported);
                }
                Value::Size {
                    index: symbol,
                    addend,
                    width: if kind == 32 { 4 } else { 8 },
                }
            }
            5 if self.linkable => {
                let reference = self.symbols.as_ref().ok_or(Error::Invalid)?.entry(symbol)?;
                let symbols::Definition::Image { value, size } =
                    reference.definition.ok_or(Error::Invalid)?
                else {
                    return Err(Error::Invalid);
                };
                if !matches!(reference.kind, 0 | 1)
                    || reference.binding == 0
                    || reference.visibility != 0
                    || reference.name.is_empty()
                    || value != target
                    || !(0..self.count).any(|index| {
                        self.segment(index).is_ok_and(|segment| {
                            segment.flags & 2 != 0 && segment.contains(target, size)
                        })
                    })
                {
                    return Err(Error::Invalid);
                }
                Value::Copy {
                    index: symbol,
                    size,
                }
            }
            1 | 6 | 7 => {
                let table = self.symbols.as_ref().ok_or(Error::Unsupported)?;
                let reference = table.entry(symbol)?;
                if reference.is_tls {
                    return Err(Error::Unsupported);
                }
                if let Some(definition) = reference.definition {
                    if let symbols::Definition::Indirect {
                        value, size, absolute,
                    } = definition {
                        if !self.linkable {
                            return Err(Error::Unsupported);
                        }
                        if !absolute {
                            self.resolver_source(value, size)?;
                        }
                    } else {
                        self.definition_value(definition)?;
                    }
                }
                if !self.linkable {
                    table.definition(symbol)?;
                }
                Value::Symbol {
                    index: symbol,
                    addend: if kind == 1 { addend } else { 0 },
                }
            }
            16..=18 | 36 if self.linkable => {
                if symbol == 0 {
                    self.tls_template(0)?.ok_or(Error::Invalid)?;
                } else {
                    let reference = self
                        .symbols
                        .as_ref()
                        .ok_or(Error::Unsupported)?
                        .entry(symbol)?;
                    if !reference.is_tls {
                        return Err(Error::Invalid);
                    }
                    if let Some(definition) = reference.definition {
                        self.tls_definition(definition)?;
                    }
                }
                Value::Tls {
                    index: symbol,
                    kind,
                    addend: if kind == 16 { 0 } else { addend },
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
            symbols::Definition::Tls { .. } | symbols::Definition::Indirect { .. } => {
                Err(Error::Unsupported)
            }
        }
    }
    fn definition_size(&self, definition: symbols::Definition, size: u64) -> Result<u64, Error> {
        match definition {
            symbols::Definition::Tls { .. } => {
                self.tls_definition(definition)?;
            }
            symbols::Definition::Indirect {
                value, size, absolute,
            } => {
                if !absolute {
                    self.resolver_source(value, size)?;
                }
            }
            _ => {
                self.definition_value(definition)?;
            }
        }
        Ok(size)
    }
    fn resolver_source(&self, value: u64, size: u64) -> Result<(), Error> {
        if (0..self.count).any(|i| {
            self.segment(i)
                .is_ok_and(|s| s.flags & 1 != 0 && s.contains(value, size.max(1)))
        }) {
            Ok(())
        } else {
            Err(Error::Invalid)
        }
    }
    fn resolver_address(&self, definition: symbols::Definition, bias: u64) -> Result<u64, Error> {
        let symbols::Definition::Indirect {
            value, size, absolute,
        } = definition else {
            return Err(Error::Invalid);
        };
        let address = if absolute { value } else { add(bias, value)? };
        let relative = address.checked_sub(bias).ok_or(Error::Invalid)?;
        self.resolver_source(relative, size)?;
        if address < USER_MIN || add(address, size.max(1))? > USER_END {
            return Err(Error::Invalid);
        }
        Ok(address)
    }
    fn tls_definition(&self, definition: symbols::Definition) -> Result<u64, Error> {
        let symbols::Definition::Tls { value, size } = definition else {
            return Err(Error::Invalid);
        };
        let template = self.tls_template(0)?.ok_or(Error::Invalid)?;
        if add(value, size)? > template.memory_size as u64 {
            return Err(Error::Invalid);
        }
        Ok(value)
    }
    pub fn requires_tls_scope(&self) -> Result<bool, Error> {
        let mut needed = false;
        self.relocations(|_, value| {
            needed |= matches!(value, Value::Tls { .. });
            Ok(())
        })?;
        Ok(needed)
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
    fn soname(&self) -> Result<Option<&[u8]>, Error> {
        let mut name = None;
        if let Some(dynamic) = self.dynamic_segment {
            for offset in extent(self.bytes, dynamic.offset, dynamic.file)?.step_by(16) {
                match u64_at(self.bytes, offset)? {
                    0 => break,
                    14 => {
                        let table = self.symbols.as_ref().ok_or(Error::Invalid)?;
                        let value = table.string(u64_at(self.bytes, offset + 8)?)?;
                        if value.is_empty() || name.replace(value).is_some() {
                            return Err(Error::Invalid);
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(name)
    }
    /// Retain the source program's PHDR view, not the native wrapper's table.
    /// A runtime linker/self-relocator interprets these with the program bias.
    pub fn executable(&self, bias: u64) -> Result<crate::process_image::Executable, Error> {
        if self.fixed && bias != 0 {
            return Err(Error::Invalid);
        }
        let program_headers = match self.source_program_headers(bias)? {
            Some(address) => address,
            None => add(self.metadata_address(bias)?, self.metadata_header_bytes())?,
        };
        Ok(crate::process_image::Executable {
            entry: add(self.entry, bias)?,
            program_headers,
            program_header_size: 56,
            program_header_count: self.count as u64,
            interpreter_base: 0,
            load_bias: bias,
        })
    }

    fn source_program_headers(&self, bias: u64) -> Result<Option<u64>, Error> {
        let offset = u64_at(self.bytes, 32)?;
        let length = (self.count as u64) * 56;
        for i in 0..self.count {
            let s = self.segment(i)?;
            if s.kind == LOAD
                && offset >= s.offset
                && add(offset, length)? <= add(s.offset, s.file)?
            {
                return Ok(Some(add(add(s.address, offset - s.offset)?, bias)?));
            }
        }
        Ok(None)
    }

    pub fn is_fixed(&self) -> bool {
        self.fixed
    }

    fn load_bounds(&self) -> Result<(u64, u64), Error> {
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
        Ok((start, end))
    }

    fn metadata_address(&self, bias: u64) -> Result<u64, Error> {
        let (start, end) = self.load_bounds()?;
        let address = if self.fixed {
            if bias != 0 || start < USER_MIN {
                return Err(Error::Invalid);
            }
            end
        } else {
            add(start, bias)?
                .checked_sub(self.metadata_bytes()?)
                .ok_or(Error::Invalid)?
        };
        if address < USER_MIN || add(address, self.metadata_bytes()?)? > USER_END {
            return Err(Error::Invalid);
        }
        Ok(address)
    }

    /// Relocatable objects are placed after a caller-selected address, including
    /// native metadata. Fixed roots retain their addresses and ignore minimum.
    /// Returns (load bias, first free page).
    pub fn placement(&self, minimum: u64) -> Result<(u64, u64), Error> {
        // A fixed root keeps its original addresses. The caller's placement
        // preference only applies to relocatable members of the scope.
        if self.fixed {
            return Ok((0, add(self.metadata_address(0)?, self.metadata_bytes()?)?));
        }
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
        if self.lifecycle.has_calls() {
            return Err(Error::Unsupported);
        }
        Ok(())
    }

    /// Compatibility marker exported by a CRT which consumes lifecycle_image.
    /// This is not executable authorization or an identity claim.
    pub fn has_lifecycle_runtime(&self) -> Result<bool, Error> {
        self.has_runtime_marker(b"__mochios_lifecycle_v1")
    }
    pub fn has_static_tls_runtime(&self) -> Result<bool, Error> {
        self.has_runtime_marker(b"__mochios_static_tls_v1")
    }
    fn has_runtime_marker(&self, name: &[u8]) -> Result<bool, Error> {
        Ok(self.runtime_function(name)?.is_some())
    }
    fn runtime_function(&self, name: &[u8]) -> Result<Option<u64>, Error> {
        let Some(table) = &self.symbols else {
            return Ok(None);
        };
        let Some(symbol) = table.find(name)? else {
            return Ok(None);
        };
        let Some(symbols::Definition::Image { value, .. }) = symbol.definition else {
            return Ok(None);
        };
        Ok((symbol.binding == 1
            && (0..self.count).any(|index| {
                self.segment(index)
                    .is_ok_and(|segment| segment.flags & 1 != 0 && segment.contains(value, 1))
            }))
        .then_some(value))
    }
    /// Template addresses refer to the prepared child at `bias`. .tbss need
    /// not lie inside a LOAD; only initialized bytes need file-backed storage.
    pub fn tls_template(&self, bias: u64) -> Result<Option<crate::static_tls::Template>, Error> {
        crate::static_tls::template(
            usize::try_from(u64_at(self.bytes, 32)?).map_err(|_| Error::Overflow)?,
            56,
            self.count,
            usize::try_from(bias).map_err(|_| Error::Overflow)?,
            |address, output| {
                let range = extent(self.bytes, address as u64, output.len() as u64)?;
                output.copy_from_slice(&self.bytes[range]);
                Ok(())
            },
        )
        .map_err(|error| match error {
            crate::static_tls::Error::InvalidImage => Error::Invalid,
            crate::static_tls::Error::Read(error) => error,
        })
    }
    pub fn alignment(&self) -> u64 {
        (0..self.count)
            .filter_map(|i| self.segment(i).ok())
            .filter(|s| s.kind == LOAD)
            .fold(PAGE, |a, s| a.max(s.alignment))
    }
    fn materialized(&self, s: Segment) -> Result<u64, Error> {
        let mut length = s.file;
        self.relocations(|target, value| {
            if s.contains(target, value.width()) {
                length = length.max(add(target - s.address, value.width())?);
            }
            Ok(())
        })?;
        Ok(length)
    }
    fn metadata_bytes(&self) -> Result<u64, Error> {
        let copy = if self.source_program_headers(0)?.is_none() {
            self.count as u64 * 56
        } else {
            0
        };
        page(add(self.metadata_header_bytes(), copy)?)
    }
    fn metadata_header_bytes(&self) -> u64 {
        64 + (self.retained as u64 + 2) * 56
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
        self.write_resolved(
            bias,
            output,
            |index, kind| {
                if matches!(kind, 32 | 33) {
                    let reference = self
                        .symbols
                        .as_ref()
                        .ok_or(Error::Unsupported)?
                        .entry(index)?;
                    return match reference.definition {
                        Some(definition) => self.definition_size(definition, reference.size),
                        None if reference.binding == 2 => Ok(0),
                        None => Err(Error::Unsupported),
                    };
                }
                if kind != 0 {
                    return Err(Error::Unsupported);
                }
                let definition = self
                    .symbols
                    .as_ref()
                    .ok_or(Error::Unsupported)?
                    .definition(index)?;
                self.definition_value(definition)?.at(bias)
            },
            |_, _| Err(Error::Unsupported),
            |_, _| Err(Error::Unsupported),
            |_, _| Ok(false),
        )
    }
    fn write_resolved(
        &self,
        bias: u64,
        output: &mut [u8],
        mut resolve: impl FnMut(u32, u32) -> Result<u64, Error>,
        mut descriptor: impl FnMut(u32, u64) -> Result<(u64, u64), Error>,
        mut copy: impl FnMut(u32, &mut [u8]) -> Result<(), Error>,
        mut deferred: impl FnMut(u64, Value) -> Result<bool, Error>,
    ) -> Result<usize, Error> {
        if bias % self.alignment() != 0 {
            return Err(Error::Invalid);
        }
        let length = self.output_length()?;
        if output.len() < length {
            return Err(Error::BufferTooSmall);
        }
        let metadata = self.metadata_bytes()?;
        let base = self.metadata_address(bias)?;
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
        if self.source_program_headers(0)?.is_none() {
            let source = extent(self.bytes, u64_at(self.bytes, 32)?, self.count as u64 * 56)?;
            let start = self.metadata_header_bytes() as usize;
            output[start..start + source.len()].copy_from_slice(&self.bytes[source]);
        }
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
                if s.contains(target, value.width()) {
                    let offset = add(destination, target - s.address)? as usize;
                    if deferred(target, value)? {
                        return Ok(());
                    }
                    if let Value::Copy { index, size } = value {
                        let end = usize::try_from(add(offset as u64, size)?)
                            .map_err(|_| Error::Overflow)?;
                        copy(
                            index,
                            output.get_mut(offset..end).ok_or(Error::BufferTooSmall)?,
                        )?;
                        return Ok(());
                    }
                    let (bytes, length) = value.encode(bias, &mut resolve, &mut descriptor)?;
                    output[offset..offset + length].copy_from_slice(&bytes[..length]);
                }
                Ok(())
            })?;
        }
        Ok(length)
    }
}
