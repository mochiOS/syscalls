//! Plan resolver calls against the selected definitions without executing them.
use super::super::{Error, Value, add, symbols::Definition};
use super::Scope;
use crate::indirect_image::{self, Access, Fixup, Region};

/// Prepared deferred work for this exact, immutable captured scope. Installing
/// the bundle also requires installing and consuming the encoded plan in the
/// receiving image after ordinary relocations/TLS and before constructors.
/// Unlike write_bundle, legacy write methods never omit resolver relocations.
pub struct Deferred<'plan, 'scope, 'image> {
    scope: &'plan Scope<'scope, 'image>,
    regions: &'plan [Region],
    fixups: &'plan mut [Fixup],
    copies: bool,
}

impl<'scope, 'image> Scope<'scope, 'image> {
    pub(super) fn indirect_fixup(
        &self,
        origin: usize,
        target: u64,
        value: Value,
    ) -> Result<Option<Fixup>, Error> {
        let object = self.objects.get(origin).ok_or(Error::Invalid)?;
        let (resolver, addend) = match value {
            Value::Indirect(value) => (
                object.image.resolver_address(
                    Definition::Indirect {
                        value,
                        size: 0,
                        absolute: false,
                    },
                    object.bias,
                )?,
                0,
            ),
            Value::Symbol { index, addend } => {
                let Some((owner, definition @ Definition::Indirect { .. }, _)) =
                    self.definition(origin, index)?
                else {
                    return Ok(None);
                };
                let owner = &self.objects[owner];
                (
                    owner.image.resolver_address(definition, owner.bias)?,
                    addend,
                )
            }
            _ => return Ok(None),
        };
        if !(0..object.image.count).any(|i| {
            object
                .image
                .segment(i)
                .is_ok_and(|s| s.flags & 2 != 0 && s.contains(target, 8))
        }) {
            return Err(Error::Invalid);
        }
        Ok(Some(Fixup::new(
            add(object.bias, target)?,
            resolver,
            addend,
        )))
    }

    /// Exact caller-owned scratch sizes (regions, fixups). This uses the same
    /// binding, visibility and version lookup as ordinary eager relocations.
    pub fn deferred_counts(&self) -> Result<(usize, usize), Error> {
        let mut regions = 0usize;
        let mut fixups = 0usize;
        for &index in self.order {
            let object = &self.objects[index];
            for i in 0..object.image.count {
                let segment = object.image.segment(i)?;
                if segment.kind == super::LOAD && segment.memory != 0 && segment.flags & 3 != 0 {
                    regions = regions.checked_add(1).ok_or(Error::Overflow)?;
                }
            }
            object.image.relocations(|target, value| {
                if self.indirect_fixup(index, target, value)?.is_some() {
                    fixups = fixups.checked_add(1).ok_or(Error::Overflow)?;
                }
                Ok(())
            })?;
        }
        if fixups != 0 {
            let mut copies = 0usize;
            self.copies(|_| {
                copies = copies.checked_add(1).ok_or(Error::Overflow)?;
                Ok(())
            })?;
            if copies != 0 {
                // COPY may read a read-only LOAD. Preserve exact ELF read bits
                // in v2 rather than deriving them from write/execute access.
                regions = 0;
                for object in self.objects {
                    for i in 0..object.image.count {
                        let s = object.image.segment(i)?;
                        if s.kind == super::LOAD && s.memory != 0 && s.flags & 7 != 0 {
                            regions = regions.checked_add(1).ok_or(Error::Overflow)?;
                        }
                    }
                }
                fixups = fixups.checked_add(copies).ok_or(Error::Overflow)?;
            }
        }
        Ok((regions, fixups))
    }

    fn copies(&self, mut emit: impl FnMut(Fixup) -> Result<(), Error>) -> Result<(), Error> {
        let root = &self.objects[0];
        root.image.relocations(|target, value| {
            if let Value::Copy { index, .. } = value {
                if let Some((provider, source, length)) = self.copy_source(index)? {
                    if length != 0 {
                        emit(Fixup::copy(
                            add(root.bias, target)?,
                            add(self.objects[provider].bias, source)?,
                            length,
                        ))?;
                    }
                }
            }
            Ok(())
        })
    }
    /// Used only after deferred_counts reports nonzero work. A v2 receiving
    /// CRT is required before publishing any runtime COPY operations.
    pub fn has_deferred_copies(&self) -> Result<bool, Error> {
        let mut found = false;
        self.copies(|_| {
            found = true;
            Ok(())
        })?;
        Ok(found)
    }

    /// Capture exact installed LOAD extents and deferred records. Sorting only
    /// regions leaves resolver ordering unchanged: dependencies before their
    /// dependents. Symbolic IFUNC writes precede IRELATIVE calls in each object;
    /// within those groups RELA precedes PLT and source table order is kept.
    /// Order scratch uses lifecycle_scratch_len() words and is not retained.
    pub fn deferred<'plan>(
        &'plan self,
        regions: &'plan mut [Region],
        fixups: &'plan mut [Fixup],
        order: &mut [usize],
    ) -> Result<Deferred<'plan, 'scope, 'image>, Error> {
        let (region_count, fixup_count) = self.deferred_counts()?;
        if regions.len() < region_count || fixups.len() < fixup_count {
            return Err(Error::BufferTooSmall);
        }
        let regions = &mut regions[..region_count];
        let fixups = &mut fixups[..fixup_count];
        let lifecycle = self.lifecycle(order)?;
        let copies = fixup_count != 0 && self.has_deferred_copies()?;
        let (mut r, mut f) = (0, 0);
        for &index in lifecycle.order() {
            let object = &self.objects[index];
            for i in 0..object.image.count {
                let s = object.image.segment(i)?;
                if s.kind == super::LOAD
                    && s.memory != 0
                    && s.flags & (if copies { 7 } else { 3 }) != 0
                {
                    regions[r] = Region {
                        address: add(object.bias, s.address)?,
                        length: s.memory,
                        access: if copies {
                            match s.flags & 7 {
                                1 => Access::Executable,
                                2 => Access::Writable,
                                4 => Access::Readable,
                                5 => Access::ReadExecute,
                                6 => Access::ReadWrite,
                                _ => return Err(Error::Invalid),
                            }
                        } else if s.flags & 1 != 0 {
                            Access::Executable
                        } else {
                            Access::Writable
                        },
                    };
                    r += 1;
                }
            }
            // The root is last in lifecycle postorder. Its COPY initializers
            // need completed providers and must precede its own resolvers.
            if copies && index == 0 {
                self.copies(|record| {
                    fixups[f] = record;
                    f += 1;
                    Ok(())
                })?;
            }
            for relative in [false, true] {
                object.image.relocations(|target, value| {
                    if matches!(value, Value::Indirect(_)) == relative {
                        if let Some(fixup) = self.indirect_fixup(index, target, value)? {
                            fixups[f] = fixup;
                            f += 1;
                        }
                    }
                    Ok(())
                })?;
            }
        }
        regions.sort_unstable_by_key(|r| r.address);
        Ok(Deferred {
            scope: self,
            regions,
            fixups,
            copies,
        })
    }
}

impl Deferred<'_, '_, '_> {
    pub fn encoded_length(&self) -> Result<usize, Error> {
        indirect_image::encoded_length(self.regions.len(), self.fixups.len())
            .map_err(|_| Error::Overflow)
    }
    pub fn encode(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        indirect_image::encode(self.regions, self.fixups, out).map_err(|error| match error {
            indirect_image::Error::BufferTooSmall => Error::BufferTooSmall,
            indirect_image::Error::TooLarge => Error::Overflow,
            _ => Error::Invalid,
        })
    }
    /// Emit all ordinary relocations. The resulting bundle is not ready to run
    /// until its resolver plan has been consumed in the receiving image.
    /// Runtime COPY uses the provider's final memory, never a resolver address
    /// or a guessed function pointer, and precedes root resolver execution.
    pub fn write_bundle(&self, out: &mut [u8]) -> Result<usize, Error> {
        self.scope
            .write_bundle_with_deferred(out, true, self.copies)
    }
}
