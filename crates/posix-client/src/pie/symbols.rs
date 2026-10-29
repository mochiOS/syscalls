//! Bounded dynamic symbol metadata. This layer never reads section headers or
//! guesses the symbol table length from adjacent tables.
use super::{Error, add, u16_at, u32_at, u64_at};
mod versions;
pub(super) use versions::Version;

#[derive(Clone, Copy)]
enum Query<'a> {
    Reference(Version<'a>),
    Export(Option<(&'a [u8], u32)>),
}

pub(super) struct Table<'a> {
    entries: &'a [u8],
    strings: &'a [u8],
    versions: versions::Versions<'a>,
    lookup: Lookup<'a>,
}

#[derive(Clone, Copy)]
pub(super) enum Definition {
    Absolute(u64),
    Image { value: u64, size: u64 },
    Tls { value: u64, size: u64 },
    Indirect {
        value: u64,
        size: u64,
        absolute: bool,
    },
}

impl<'a> Table<'a> {
    // HASH, STRTAB, SYMTAB, STRSZ, SYMENT, GNU_HASH.
    pub(super) fn parse(
        tags: [Option<u64>; 6],
        version_tags: [Option<u64>; 5],
        required_symbols: u64,
        read: impl Fn(u64, u64) -> Result<&'a [u8], Error>,
    ) -> Result<Self, Error> {
        let [hash, strings, entries, string_size, entry_size, gnu_hash] = tags;
        if entry_size != Some(24) {
            return Err(Error::Invalid);
        }
        let mut count = None;
        let mut lookup = None;
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
            let split = 8 + buckets as usize * 4;
            lookup = Some(Lookup::Sysv {
                buckets: &table[8..split],
                chains: &table[split..],
            });
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
            if count.is_some_and(|count| {
                if highest == 0 {
                    first > count
                } else {
                    count != end
                }
            }) {
                return Err(Error::Invalid);
            }
            let chain_address = add(address, prefix.len() as u64)?;
            let chains = read(
                chain_address,
                (end - first).checked_mul(4).ok_or(Error::Overflow)?,
            )?;
            lookup = Some(Lookup::Gnu {
                buckets: &prefix[bucket_offset as usize..],
                chains,
                first: first as u32,
            });
            // An empty GNU hash has no hashed suffix. Some linkers use
            // symoffset=1 even when imports follow the null symbol. Retain
            // an exact SysV count, or capture the prefix addressed by RELA.
            count = Some(if highest == 0 {
                count.unwrap_or(first.max(required_symbols))
            } else {
                end
            });
        }
        let count = count.ok_or(Error::Unsupported)?;
        if count < required_symbols {
            return Err(Error::Invalid);
        }
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
        let versions = versions::Versions::parse(version_tags, entries, strings, &read)?;
        Ok(Self {
            entries,
            strings,
            versions,
            lookup: lookup.ok_or(Error::Unsupported)?,
        })
    }

    pub(super) fn string(&self, offset: u64) -> Result<&'a [u8], Error> {
        string(self.strings, offset)
    }

    pub(super) fn entry(&self, index: u32) -> Result<Entry<'a>, Error> {
        let offset = (index as usize).checked_mul(24).ok_or(Error::Overflow)?;
        let entry = self
            .entries
            .get(offset..offset.checked_add(24).ok_or(Error::Overflow)?)
            .ok_or(Error::Invalid)?;
        let name = self.string(u32_at(entry, 0)? as u64)?;
        let binding = entry[4] >> 4;
        let kind = entry[4] & 15;
        if binding > 2 || !matches!(kind, 0..=3 | 6 | 10) || entry[5] & !3 != 0 {
            return Err(Error::Unsupported);
        }
        let section = u16_at(entry, 6)?;
        let value = u64_at(entry, 8)?;
        let definition = match section {
            0 if index == 0 => Some(Definition::Absolute(0)),
            0 => None,
            0xfff1 if kind == 10 => Some(Definition::Indirect {
                value,
                size: u64_at(entry, 16)?,
                absolute: true,
            }),
            0xfff1 if kind != 6 => Some(Definition::Absolute(value)),
            0xff00..=0xffff => return Err(Error::Unsupported),
            _ if kind == 6 => Some(Definition::Tls {
                value,
                size: u64_at(entry, 16)?,
            }),
            _ if kind == 10 => Some(Definition::Indirect {
                value,
                size: u64_at(entry, 16)?,
                absolute: false,
            }),
            _ => Some(Definition::Image {
                value,
                size: u64_at(entry, 16)?,
            }),
        };
        Ok(Entry {
            name,
            size: u64_at(entry, 16)?,
            binding,
            visibility: entry[5],
            definition,
            is_tls: kind == 6,
            kind,
            version: self.versions.at(index)?,
        })
    }

    pub(super) fn definition(&self, index: u32) -> Result<Definition, Error> {
        let entry = self.entry(index)?;
        entry
            .definition
            .or_else(|| (entry.binding == 2).then_some(Definition::Absolute(0)))
            .ok_or(Error::Unsupported)
    }

    pub(super) fn validate_imported_definitions(
        &self,
        mut copied: impl FnMut(u64, u64) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        for (index, raw) in self.entries.chunks_exact(24).enumerate() {
            if u16_at(raw, 6)? != 0
                && matches!(
                    self.versions.at(index as u32)?,
                    Version::Named { imported: true, .. }
                )
            {
                let entry = self.entry(index as u32)?;
                let Some(Definition::Image { value, size }) = entry.definition else {
                    return Err(Error::Invalid);
                };
                if !matches!(entry.kind, 0 | 1) || !copied(value, size)? {
                    return Err(Error::Invalid);
                }
            }
        }
        Ok(())
    }

    fn matching(
        &self,
        index: u32,
        name: &[u8],
        query: Query<'_>,
    ) -> Result<Option<(Entry<'a>, bool)>, Error> {
        let offset = (index as usize).checked_mul(24).ok_or(Error::Overflow)?;
        let raw = self
            .entries
            .get(offset..offset.checked_add(24).ok_or(Error::Overflow)?)
            .ok_or(Error::Invalid)?;
        if self.string(u32_at(raw, 0)? as u64)? != name {
            return Ok(None);
        }
        // Non-exported records must not participate, including hidden TLS or
        // IFUNC records which need no resolution for this external lookup.
        if raw[4] >> 4 == 0 || matches!(raw[5] & 3, 1 | 2) || u16_at(raw, 6)? == 0 {
            return Ok(None);
        }
        if matches!(query, Query::Export(_)) && matches!(raw[4] & 15, 3 | 4) {
            return Ok(None);
        }
        let version = self.versions.at(index)?;
        let fallback = match query {
            Query::Export(None) => match version {
                Version::Local | Version::Named { hidden: true, .. } => return Ok(None),
                Version::Named { .. } => true,
                _ => false,
            },
            Query::Export(Some((requested, digest))) => match version {
                Version::Named { name, hash, .. } if name == requested && hash == digest => false,
                Version::Unversioned => false,
                Version::Global if requested.is_empty() => false,
                _ => return Ok(None),
            },
            Query::Reference(required) => match (required, version) {
                (_, Version::Local) | (Version::Local, _) => return Ok(None),
                (
                    Version::Named { name, hash, .. },
                    Version::Named {
                        name: other,
                        hash: digest,
                        ..
                    },
                ) => {
                    if name != other || hash != digest {
                        return Ok(None);
                    }
                    false
                }
                (Version::Named { strict, .. }, Version::Global) => {
                    if strict {
                        return Ok(None);
                    }
                    true
                }
                (Version::Named { .. }, Version::Unversioned) => false,
                (_, Version::Named { index: 2, .. }) => false,
                (_, Version::Named { hidden: true, .. }) => return Ok(None),
                (_, Version::Named { .. }) => true,
                _ => false,
            },
        };
        let entry = self.entry(index)?;
        if entry.binding != 0 && !matches!(entry.visibility, 1 | 2) && entry.definition.is_some() {
            Ok(Some((entry, fallback)))
        } else {
            Ok(None)
        }
    }

    pub(super) fn find(&self, name: &[u8]) -> Result<Option<Entry<'a>>, Error> {
        self.find_versioned(name, Version::Global)
    }

    pub(super) fn find_versioned(
        &self,
        name: &[u8],
        required: Version<'_>,
    ) -> Result<Option<Entry<'a>>, Error> {
        self.find_query(name, Query::Reference(required))
    }

    pub(super) fn find_export(
        &self,
        name: &[u8],
        version: Option<&[u8]>,
    ) -> Result<Option<Entry<'a>>, Error> {
        self.find_query(name, Query::Export(version.map(|v| (v, versions::hash(v)))))
    }

    fn find_query(&self, name: &[u8], query: Query<'_>) -> Result<Option<Entry<'a>>, Error> {
        let mut fallback = None;
        let mut matches = 0usize;
        let consider = |index,
                        matches: &mut usize,
                        fallback: &mut Option<Entry<'a>>|
         -> Result<Option<Entry<'a>>, Error> {
            if let Some((entry, deferred)) = self.matching(index, name, query)? {
                if !deferred {
                    return Ok(Some(entry));
                }
                *matches += 1;
                *fallback = Some(entry);
            }
            Ok(None)
        };
        match self.lookup {
            Lookup::Sysv { buckets, chains } => {
                let hash = versions::hash(name);
                let mut index = u32_at(buckets, hash as usize % (buckets.len() / 4) * 4)?;
                // Corrupt chain cycles must terminate with an error, not hang.
                for _ in 0..self.entries.len() / 24 {
                    if index == 0 {
                        return Ok(if matches == 1 { fallback } else { None });
                    }
                    if let Some(entry) = consider(index, &mut matches, &mut fallback)? {
                        return Ok(Some(entry));
                    }
                    index = u32_at(chains, index as usize * 4)?;
                }
                Err(Error::Invalid)
            }
            Lookup::Gnu {
                buckets,
                chains,
                first,
            } => {
                let hash = name.iter().fold(5381u32, |hash, byte| {
                    hash.wrapping_mul(33).wrapping_add(*byte as u32)
                });
                let mut index = u32_at(buckets, hash as usize % (buckets.len() / 4) * 4)?;
                if index == 0 {
                    return Ok(None);
                }
                loop {
                    let within = index.checked_sub(first).ok_or(Error::Invalid)?;
                    let chain = u32_at(chains, within as usize * 4)?;
                    if chain | 1 == hash | 1 {
                        if let Some(entry) = consider(index, &mut matches, &mut fallback)? {
                            return Ok(Some(entry));
                        }
                    }
                    if chain & 1 != 0 {
                        return Ok(if matches == 1 { fallback } else { None });
                    }
                    index = index.checked_add(1).ok_or(Error::Overflow)?;
                }
            }
        }
    }

    pub(super) fn requirements(
        &self,
        mut visit: impl FnMut(&[u8], &[u8], u32, bool) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.versions.requirements(|node| {
            visit(
                node.file.ok_or(Error::Invalid)?,
                node.name,
                node.hash,
                node.weak,
            )
        })
    }

    pub(super) fn provides(&self, name: &[u8], hash: u32) -> Result<bool, Error> {
        self.versions.provides(name, hash)
    }
}

fn string(strings: &[u8], offset: u64) -> Result<&[u8], Error> {
    let offset = usize::try_from(offset).map_err(|_| Error::Overflow)?;
    let tail = strings.get(offset..).ok_or(Error::Invalid)?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::Invalid)?;
    Ok(&tail[..end])
}

pub(super) struct Entry<'a> {
    pub size: u64,
    pub name: &'a [u8],
    pub binding: u8,
    pub visibility: u8,
    pub definition: Option<Definition>,
    pub is_tls: bool,
    pub kind: u8,
    pub version: Version<'a>,
}

#[derive(Clone, Copy)]
enum Lookup<'a> {
    Sysv {
        buckets: &'a [u8],
        chains: &'a [u8],
    },
    Gnu {
        buckets: &'a [u8],
        chains: &'a [u8],
        first: u32,
    },
}
