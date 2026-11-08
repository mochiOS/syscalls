//! Versioned, bounded userspace loader metadata. This is not a kernel ABI or
//! an authority token. Captured ELF metadata remains usable without reopening
//! a pathname or trusting mutable program headers in running application code.
use crate::{newlib_errno::*, pie::link_scope::Object};
const MAGIC: &[u8; 8] = b"MLOAD001";
const HEADER: usize = 24;
const RECORD: usize = 64;
pub const MAX_BYTES: usize = 16 * 1024 * 1024;

fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn align(value: usize) -> Result<usize, i32> {
    value.checked_add(7).map(|n| n & !7).ok_or(E2BIG)
}

/// Required size for all captured objects, including NUL-terminated names.
pub fn encoded_length(objects: &[Object<'_, '_>], root_name: &[u8]) -> Result<usize, i32> {
    if objects.is_empty()
        || root_name.contains(&0)
        || objects.iter().any(|object| object.name.contains(&0))
    {
        return Err(EINVAL);
    }
    let mut size = HEADER
        .checked_add(objects.len().checked_mul(RECORD).ok_or(E2BIG)?)
        .ok_or(E2BIG)?;
    for (index, object) in objects.iter().enumerate() {
        let (headers, symbols, strings) = object.image.inspection();
        for bytes in [
            headers,
            symbols,
            strings,
            if index == 0 { root_name } else { object.name },
        ] {
            size = align(size)?.checked_add(bytes.len()).ok_or(E2BIG)?;
        }
        size = size
            .checked_add(1)
            .filter(|n| *n <= MAX_BYTES)
            .ok_or(E2BIG)?;
    }
    Ok(size)
}

/// Encode only already parsed objects. Paths/names are informational, never
/// used to acquire executable authority. The destination is fully initialized.
pub fn encode(objects: &[Object<'_, '_>], root_name: &[u8], output: &mut [u8]) -> Result<(), i32> {
    let length = encoded_length(objects, root_name)?;
    if output.len() != length {
        return Err(EINVAL);
    }
    output.fill(0);
    output[..8].copy_from_slice(MAGIC);
    put(output, 8, length as u64);
    put(output, 16, objects.len() as u64);
    let mut cursor = HEADER + objects.len() * RECORD;
    for (index, object) in objects.iter().enumerate() {
        let at = HEADER + index * RECORD;
        let (headers, symbols, strings) = object.image.inspection();
        put(output, at, object.bias);
        for (offset, count_offset, bytes, count) in [
            (8, 16, headers, headers.len() / 56),
            (40, 48, symbols, symbols.len() / 24),
            (56, usize::MAX, strings, 0),
            (
                24,
                32,
                if index == 0 { root_name } else { object.name },
                if index == 0 {
                    root_name.len()
                } else {
                    object.name.len()
                },
            ),
        ] {
            cursor = align(cursor)?;
            put(output, at + offset, cursor as u64);
            if count_offset != usize::MAX {
                put(output, at + count_offset, count as u64);
            }
            output[cursor..cursor + bytes.len()].copy_from_slice(bytes);
            cursor += bytes.len();
        }
        cursor += 1; // object name terminator
    }
    Ok(())
}

/// Validated immutable snapshot. Parse checks all offsets before iteration.
pub struct Image<'a> {
    bytes: &'a [u8],
    count: usize,
}
/// One object's informational names, relocation bias and ELF program headers.
pub struct Entry<'a> {
    pub bias: u64,
    pub name: &'a [u8],
    pub headers: &'a [u8],
    symbols: &'a [u8],
    strings: &'a [u8],
}
impl<'a> Image<'a> {
    /// Validate the version, complete record table, names, spans and address
    /// arithmetic before any object view can be obtained. Does not grant trust.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, i32> {
        if bytes.len() < HEADER
            || bytes.len() > MAX_BYTES
            || &bytes[..8] != MAGIC
            || word(bytes, 8) != bytes.len() as u64
        {
            return Err(ENOEXEC);
        }
        let count = usize::try_from(word(bytes, 16)).map_err(|_| ENOEXEC)?;
        if count == 0
            || count
                .checked_mul(RECORD)
                .and_then(|n| n.checked_add(HEADER))
                .filter(|n| *n <= bytes.len())
                .is_none()
        {
            return Err(ENOEXEC);
        }
        let image = Self { bytes, count };
        for index in 0..count {
            image.entry(index)?;
        }
        Ok(image)
    }
    /// Number of captured objects in loader order.
    pub fn count(&self) -> usize {
        self.count
    }
    /// Borrow one validated object; an out-of-range index returns EINVAL.
    pub fn entry(&self, index: usize) -> Result<Entry<'a>, i32> {
        if index >= self.count {
            return Err(EINVAL);
        }
        let at = HEADER + index * RECORD;
        let offset = |field| usize::try_from(word(self.bytes, at + field)).map_err(|_| ENOEXEC);
        let span = |field, count_field, width: usize| -> Result<&'a [u8], i32> {
            let first = offset(field)?;
            let length = offset(count_field)?.checked_mul(width).ok_or(ENOEXEC)?;
            if first < HEADER + self.count * RECORD || first % 8 != 0 {
                return Err(ENOEXEC);
            }
            self.bytes
                .get(first..first.checked_add(length).ok_or(ENOEXEC)?)
                .ok_or(ENOEXEC)
        };
        let name = span(24, 32, 1)?;
        if self
            .bytes
            .get(offset(24)?.checked_add(name.len()).ok_or(ENOEXEC)?)
            != Some(&0)
            || name.contains(&0)
        {
            return Err(ENOEXEC);
        }
        let strings_start = offset(56)?;
        let name_start = offset(24)?;
        if strings_start > name_start || strings_start < HEADER + self.count * RECORD {
            return Err(ENOEXEC);
        }
        let entry = Entry {
            bias: word(self.bytes, at),
            name,
            headers: span(8, 16, 56)?,
            symbols: span(40, 48, 24)?,
            strings: &self.bytes[strings_start..name_start],
        };
        if entry.headers.is_empty() {
            return Err(ENOEXEC);
        }
        for header in entry.headers.chunks_exact(56) {
            if word(header, 16)
                .checked_add(entry.bias)
                .and_then(|n| n.checked_add(word(header, 40)))
                .filter(|n| *n <= 0x8000_0000_0000)
                .is_none()
            {
                return Err(ENOEXEC);
            }
        }
        Ok(entry)
    }
}
impl<'a> Entry<'a> {
    /// Lowest mapped LOAD address, which differs from relocation bias for
    /// fixed-address ET_EXEC objects and libraries with a nonzero first LOAD.
    pub fn base(&self) -> u64 {
        self.headers
            .chunks_exact(56)
            .filter(|h| u32::from_le_bytes(h[..4].try_into().unwrap()) == 1)
            .map(|h| (self.bias + word(h, 16)) & !4095)
            .min()
            .unwrap_or(self.bias)
    }
    /// Match actual LOAD extents; gaps between segments do not belong here.
    pub fn contains(&self, address: u64) -> bool {
        self.headers.chunks_exact(56).any(|h| {
            u32::from_le_bytes(h[..4].try_into().unwrap()) == 1
                && address >= self.bias + word(h, 16)
                && address < self.bias + word(h, 16) + word(h, 40)
        })
    }
    /// Nearest exported non-TLS, non-IFUNC definition at or before address.
    /// Returned names borrow the immutable snapshot, never temporary storage.
    pub fn symbol(&self, address: u64) -> Option<(&'a [u8], u64)> {
        let mut found = None;
        for symbol in self.symbols.chunks_exact(24) {
            let info = symbol[4];
            if !matches!(info >> 4, 1 | 2)
                || !matches!(info & 15, 0 | 1 | 2)
                || !matches!(symbol[5] & 3, 0 | 3)
                || u16::from_le_bytes(symbol[6..8].try_into().unwrap()) == 0
            {
                continue;
            }
            let value = word(symbol, 8);
            let absolute = u16::from_le_bytes(symbol[6..8].try_into().unwrap()) == 0xfff1;
            let start = if absolute {
                value
            } else {
                self.bias.checked_add(value)?
            };
            if start > address || found.is_some_and(|(_, previous)| previous > start) {
                continue;
            }
            let offset = u32::from_le_bytes(symbol[..4].try_into().unwrap()) as usize;
            let tail = self.strings.get(offset..)?;
            let end = tail.iter().position(|b| *b == 0)?;
            if end != 0 {
                found = Some((&tail[..end], start));
            }
        }
        found
    }
}
