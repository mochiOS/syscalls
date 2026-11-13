//! GNU version tables, captured through LOAD ranges rather than section names.
//! All chains are counted, forward-only and validated before symbol lookup.
use super::{Error, add, string, u16_at, u32_at};

pub(super) fn hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;
    for &byte in name {
        hash = hash.wrapping_shl(4).wrapping_add(byte as u32);
        let high = hash & 0xf0000000;
        hash ^= high >> 24;
        hash &= !high;
    }
    hash
}

#[derive(Clone, Copy)]
pub(in super::super) enum Version<'a> {
    Unversioned,
    Local,
    Global,
    Named {
        name: &'a [u8],
        hash: u32,
        index: u16,
        hidden: bool,
        strict: bool,
        imported: bool,
    },
}

#[derive(Clone, Copy)]
pub(super) struct Node<'a> {
    index: u16,
    pub name: &'a [u8],
    pub hash: u32,
    pub file: Option<&'a [u8]>,
    pub weak: bool,
    strict: bool,
}

#[derive(Default)]
struct Records<'a> {
    bytes: &'a [u8],
    count: usize,
    definitions: bool,
}
impl<'a> Records<'a> {
    fn capture(
        address: Option<u64>,
        count: Option<u64>,
        definitions: bool,
        read: &impl Fn(u64, u64) -> Result<&'a [u8], Error>,
    ) -> Result<Self, Error> {
        let (address, count) = match (address, count) {
            (None, None) => return Ok(Self::default()),
            (Some(address), Some(count @ 1..=0x7fff)) => (address, count as usize),
            _ => return Err(Error::Invalid),
        };
        let header = if definitions { 20 } else { 16 };
        let auxiliary = if definitions { 8 } else { 16 };
        let mut offset = 0;
        let mut length = 0;
        let mut previous_aux_end = 0;
        let mut header_offset = 0;
        let mut header_index = 0;
        for index in 0..count {
            let record = read(add(address, offset)?, header)?;
            if u16_at(record, 0)? != 1 {
                return Err(Error::Unsupported);
            }
            let number = u16_at(record, if definitions { 6 } else { 2 })?;
            if number == 0 {
                return Err(Error::Invalid);
            }
            let mut aux = u32_at(record, if definitions { 12 } else { 8 })? as u64;
            if aux < header || aux % 4 != 0 {
                return Err(Error::Invalid);
            }
            for entry in 0..number {
                let bytes = read(add(add(address, offset)?, aux)?, auxiliary)?;
                let start = add(offset, aux)?;
                let end = add(start, auxiliary)?;
                if start < previous_aux_end { return Err(Error::Invalid); }
                previous_aux_end = end;
                length = length.max(end);
                // Accept both interleaved GNU ld records and lld's packed
                // headers. Both chains remain forward, disjoint and bounded.
                // Their independent cursors keep this allocation-free/linear.
                while header_index < count {
                    if add(header_offset, header)? > start {
                        if header_offset < end { return Err(Error::Invalid); }
                        break;
                    }
                    let entry = read(add(address, header_offset)?, header)?;
                    let next = u32_at(entry, if definitions { 16 } else { 12 })? as u64;
                    header_index += 1;
                    if header_index < count {
                        if next < header || next % 4 != 0 { return Err(Error::Invalid); }
                        header_offset = add(header_offset, next)?;
                    } else if next != 0 { return Err(Error::Invalid); }
                }
                let next = u32_at(bytes, if definitions { 4 } else { 12 })? as u64;
                if entry + 1 == number {
                    if next != 0 {
                        return Err(Error::Invalid);
                    }
                } else {
                    if next < auxiliary || next % 4 != 0 {
                        return Err(Error::Invalid);
                    }
                    aux = add(aux, next)?;
                }
            }
            let next = u32_at(record, if definitions { 16 } else { 12 })? as u64;
            if index + 1 == count {
                if next != 0 {
                    return Err(Error::Invalid);
                }
            } else {
                if next < header || next % 4 != 0 {
                    return Err(Error::Invalid);
                }
                offset = add(offset, next)?;
            }
        }
        Ok(Self {
            bytes: read(address, length)?,
            count,
            definitions,
        })
    }

    fn visit(
        &self,
        strings: &'a [u8],
        mut visit: impl FnMut(Node<'a>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut offset = 0;
        for _ in 0..self.count {
            let record = &self.bytes[offset..];
            let definitions = self.definitions;
            let number = u16_at(record, if definitions { 6 } else { 2 })?;
            let file = if definitions {
                None
            } else {
                Some(string(strings, u32_at(record, 4)? as u64)?)
            };
            if file == Some(b"".as_slice()) {
                return Err(Error::Invalid);
            }
            let mut aux = u32_at(record, if definitions { 12 } else { 8 })? as usize;
            for index in 0..number {
                let bytes = &record[aux..];
                let name = string(
                    strings,
                    u32_at(bytes, if definitions { 0 } else { 8 })? as u64,
                )?;
                if name.is_empty() {
                    return Err(Error::Invalid);
                }
                if !definitions || index == 0 {
                    let (id, flags, digest) = if definitions {
                        (u16_at(record, 4)?, u16_at(record, 2)?, u32_at(record, 8)?)
                    } else {
                        (u16_at(bytes, 6)?, u16_at(bytes, 4)?, u32_at(bytes, 0)?)
                    };
                    if flags & !(if definitions { 3 } else { 2 }) != 0 {
                        return Err(Error::Unsupported);
                    }
                    let number = id & 0x7fff;
                    if hash(name) != digest
                        || number == 0
                        || (definitions && (id != number || (number == 1) != (flags & 1 != 0)))
                        || (!definitions && number == 1)
                    {
                        return Err(Error::Invalid);
                    }
                    visit(Node {
                        index: number,
                        name,
                        hash: digest,
                        file,
                        weak: flags & 2 != 0,
                        strict: !definitions && id & 0x8000 != 0,
                    })?;
                }
                aux += u32_at(bytes, if definitions { 4 } else { 12 })? as usize;
            }
            offset += u32_at(record, if definitions { 16 } else { 12 })? as usize;
        }
        Ok(())
    }
}

pub(super) struct Versions<'a> {
    symbols: &'a [u8],
    strings: &'a [u8],
    definitions: Records<'a>,
    needs: Records<'a>,
}
impl<'a> Versions<'a> {
    pub fn parse(
        tags: [Option<u64>; 5],
        entries: &[u8],
        strings: &'a [u8],
        read: &impl Fn(u64, u64) -> Result<&'a [u8], Error>,
    ) -> Result<Self, Error> {
        let [symbols, definitions, definition_count, needs, need_count] = tags;
        let definitions = Records::capture(definitions, definition_count, true, read)?;
        let needs = Records::capture(needs, need_count, false, read)?;
        let symbols = match symbols {
            Some(address) => read(address, (entries.len() / 24) as u64 * 2)?,
            None if definitions.count == 0 && needs.count == 0 => &[],
            None => return Err(Error::Invalid),
        };
        let result = Self {
            symbols,
            strings,
            definitions,
            needs,
        };
        // Version indices are 15 bits. Fixed bitsets bound duplicate checking
        // without allocation or a quadratic scan of every preceding record.
        let mut seen = [0u64; 512];
        let mut defined = [0u64; 512];
        for records in [&result.definitions, &result.needs] {
            records.visit(strings, |node| {
                let slot = node.index as usize / 64;
                let mask = 1u64 << (node.index % 64);
                if seen[slot] & mask != 0 {
                    return Err(Error::Invalid);
                }
                seen[slot] |= mask;
                if node.file.is_none() {
                    defined[slot] |= mask;
                }
                Ok(())
            })?;
        }
        for (index, bytes) in symbols.chunks_exact(2).enumerate() {
            let raw = u16_at(bytes, 0)?;
            let id = raw & 0x7fff;
            if (index == 0 && raw != 0) || (id <= 1 && raw != id) {
                return Err(Error::Invalid);
            }
            if id > 1 {
                let mask = 1u64 << (id % 64);
                let slot = id as usize / 64;
                if seen[slot] & mask == 0 {
                    return Err(Error::Invalid);
                }
                let has_definition = u16_at(entries, index * 24 + 6)? != 0;
                if !has_definition && defined[slot] & mask != 0 {
                    return Err(Error::Unsupported);
                }
            }
        }
        Ok(result)
    }

    pub fn at(&self, index: u32) -> Result<Version<'a>, Error> {
        if self.symbols.is_empty() {
            return Ok(Version::Unversioned);
        }
        let raw = u16_at(self.symbols, index as usize * 2)?;
        let id = raw & 0x7fff;
        match id {
            0 => Ok(Version::Local),
            1 => Ok(Version::Global),
            _ => {
                let mut found = None;
                for records in [&self.definitions, &self.needs] {
                    records.visit(self.strings, |node| {
                        if node.index == id {
                            found = Some(Version::Named {
                                name: node.name,
                                hash: node.hash,
                                index: id,
                                hidden: raw & 0x8000 != 0,
                                strict: node.strict,
                                imported: node.file.is_some(),
                            });
                        }
                        Ok(())
                    })?;
                }
                found.ok_or(Error::Invalid)
            }
        }
    }

    pub fn requirements(
        &self,
        visit: impl FnMut(Node<'a>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.needs.visit(self.strings, visit)
    }

    pub fn provides(&self, name: &[u8], hash: u32) -> Result<bool, Error> {
        // Unversioned objects may interpose versioned references, as with GNU
        // symbol lookup. A versioned provider must contain the requested node.
        let mut found = self.definitions.count == 0;
        self.definitions.visit(self.strings, |node| {
            found |= node.index != 1 && node.hash == hash && node.name == name;
            Ok(())
        })?;
        Ok(found)
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    fn w16(bytes: &mut [u8], at: usize, value: u16) { bytes[at..at+2].copy_from_slice(&value.to_le_bytes()); }
    fn w32(bytes: &mut [u8], at: usize, value: u32) { bytes[at..at+4].copy_from_slice(&value.to_le_bytes()); }
    fn fixture(packed: bool) -> [u8; 64] {
        let mut bytes = [0; 64];
        for (header, aux, next, id) in if packed { [(0,32,16,2), (16,48,0,3)] } else { [(0,16,32,2),(32,48,0,3)] } {
            w16(&mut bytes, header, 1); w16(&mut bytes, header+2, 1);
            w32(&mut bytes, header+4, 1); w32(&mut bytes, header+8, (aux-header) as u32); w32(&mut bytes, header+12, next);
            let name = if id==2 { b"API_1".as_slice() } else { b"API_2".as_slice() };
            w32(&mut bytes, aux, hash(name)); w16(&mut bytes, aux+6, id);
            w32(&mut bytes, aux+8, if id==2 {15} else {21});
        }
        bytes
    }
    fn parse(bytes: &[u8]) -> Result<Records<'_>, Error> {
        Records::capture(Some(0x1000), Some(2), false, &|address,length| {
            let start=usize::try_from(address.checked_sub(0x1000).ok_or(Error::Invalid)?).map_err(|_|Error::Overflow)?;
            bytes.get(start..start.checked_add(length as usize).ok_or(Error::Overflow)?).ok_or(Error::Invalid)
        })
    }
    #[test]
    fn packed_and_interleaved_headers_preserve_the_same_version_requirements() {
        for packed in [false,true] {
            let bytes=fixture(packed); let records=parse(&bytes).unwrap();
            let mut seen=0;
            records.visit(b"\0libfixture.so\0API_1\0API_2\0", |node| {
                assert_eq!(node.file,Some(b"libfixture.so".as_slice()));
                assert_eq!(node.index,seen+2); seen+=1; Ok(())
            }).unwrap();
            assert_eq!(seen,2);
        }
    }
    #[test]
    fn auxiliary_header_overlap_is_rejected() {
        let mut bytes=fixture(true);w32(&mut bytes,8,16);assert!(parse(&bytes).is_err());
    }
    #[test]
    fn auxiliary_reuse_and_nonforward_headers_are_rejected() {
        let mut bytes=fixture(true);w32(&mut bytes,24,16);assert!(parse(&bytes).is_err());
        let mut bytes=fixture(true);w32(&mut bytes,12,8);assert!(parse(&bytes).is_err());
        let mut bytes=fixture(true);w32(&mut bytes,12,0);assert!(parse(&bytes).is_err());
    }
    #[test]
    fn truncated_auxiliary_records_and_nonzero_final_links_are_rejected() {
        let bytes=fixture(true);assert!(parse(&bytes[..63]).is_err());
        let mut bytes=fixture(true);w32(&mut bytes,60,16);assert!(parse(&bytes).is_err());
        let mut bytes=fixture(true);w32(&mut bytes,28,16);assert!(parse(&bytes).is_err());
    }
}
