//! Bounded dynamic symbol metadata. This layer never reads section headers or
//! guesses the symbol table length from adjacent tables.
use super::{Error, add, u16_at, u32_at, u64_at};

pub(super) struct Table<'a> {
    entries: &'a [u8],
    strings: &'a [u8],
    versioned: bool,
}

pub(super) enum Definition {
    Absolute(u64),
    Image { value: u64, size: u64 },
}

impl<'a> Table<'a> {
    // HASH, STRTAB, SYMTAB, STRSZ, SYMENT, GNU_HASH.
    pub(super) fn parse(
        tags: [Option<u64>; 6],
        versioned: bool,
        read: impl Fn(u64, u64) -> Result<&'a [u8], Error>,
    ) -> Result<Self, Error> {
        let [hash, strings, entries, string_size, entry_size, gnu_hash] = tags;
        if entry_size != Some(24) {
            return Err(Error::Invalid);
        }
        let mut count = None;
        if let Some(address) = hash {
            let header = read(address, 8)?;
            let buckets = u32_at(header, 0)? as u64;
            let chains = u32_at(header, 4)? as u64;
            if buckets == 0 || chains == 0 {
                return Err(Error::Invalid);
            }
            let table = read(address, add(8, add(buckets, chains)? * 4)?)?;
            for offset in (8..table.len()).step_by(4) {
                if u32_at(table, offset)? as u64 >= chains {
                    return Err(Error::Invalid);
                }
            }
            count = Some(chains);
        }
        if let Some(address) = gnu_hash {
            let header = read(address, 16)?;
            let buckets = u32_at(header, 0)? as u64;
            let first = u32_at(header, 4)? as u64;
            let bloom = u32_at(header, 8)? as u64;
            if buckets == 0 || first == 0 || !bloom.is_power_of_two() {
                return Err(Error::Invalid);
            }
            let bucket_offset = add(16, bloom * 8)?;
            let prefix = read(address, add(bucket_offset, buckets * 4)?)?;
            let mut highest = 0;
            for offset in (bucket_offset as usize..prefix.len()).step_by(4) {
                let bucket = u32_at(prefix, offset)? as u64;
                if bucket != 0 && bucket < first {
                    return Err(Error::Invalid);
                }
                highest = highest.max(bucket);
            }
            let mut end = first;
            if highest != 0 {
                let chain_base = add(address, prefix.len() as u64)?;
                end = highest;
                loop {
                    let offset = (end - first).checked_mul(4).ok_or(Error::Overflow)?;
                    let word = u32_at(read(add(chain_base, offset)?, 4)?, 0)?;
                    end = add(end, 1)?;
                    if word & 1 != 0 {
                        break;
                    }
                }
            }
            if count.is_some_and(|count| count != end) {
                return Err(Error::Invalid);
            }
            count = Some(end);
        }
        let count = count.ok_or(Error::Unsupported)?;
        let entries = read(
            entries.ok_or(Error::Invalid)?,
            count.checked_mul(24).ok_or(Error::Overflow)?,
        )?;
        let strings = read(
            strings.ok_or(Error::Invalid)?,
            string_size.ok_or(Error::Invalid)?,
        )?;
        if entries[..24].iter().any(|byte| *byte != 0)
            || strings.first() != Some(&0)
            || strings.last() != Some(&0)
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            entries,
            strings,
            versioned,
        })
    }

    pub(super) fn definition(&self, index: u32) -> Result<Definition, Error> {
        if self.versioned {
            return Err(Error::Unsupported);
        }
        let offset = (index as usize).checked_mul(24).ok_or(Error::Overflow)?;
        let entry = self
            .entries
            .get(offset..offset.checked_add(24).ok_or(Error::Overflow)?)
            .ok_or(Error::Invalid)?;
        let name = u32_at(entry, 0)? as usize;
        if !self
            .strings
            .get(name..)
            .is_some_and(|name| name.contains(&0))
        {
            return Err(Error::Invalid);
        }
        let binding = entry[4] >> 4;
        let kind = entry[4] & 15;
        if binding > 2 || !matches!(kind, 0..=3) || entry[5] & !3 != 0 {
            return Err(Error::Unsupported);
        }
        let section = u16_at(entry, 6)?;
        let value = u64_at(entry, 8)?;
        match section {
            0 if index == 0 || binding == 2 => Ok(Definition::Absolute(0)),
            0 => Err(Error::Unsupported),
            0xfff1 => Ok(Definition::Absolute(value)),
            0xff00..=0xffff => Err(Error::Unsupported),
            _ => Ok(Definition::Image {
                value,
                size: u64_at(entry, 16)?,
            }),
        }
    }
}
