//! Explicit, borrowed link scope. Filesystem discovery, Handle acquisition and
//! execution authority remain the caller's responsibility; no path is opened.
use super::{Error, LOAD, PAGE, Pie, USER_END, USER_MIN, add, page};

pub struct Object<'scope, 'image> {
    /// Name by which this already-captured object satisfies DT_NEEDED.
    pub name: &'scope [u8],
    pub image: &'scope Pie<'image>,
    pub bias: u64,
}

pub struct Scope<'scope, 'image> {
    objects: &'scope [Object<'scope, 'image>],
    order: &'scope [usize],
}
impl<'scope, 'image> Scope<'scope, 'image> {
    /// Object zero is the root. Derive breadth-first search order from its
    /// DT_NEEDED graph, deduplicating cycles and shared dependencies in scratch.
    pub fn new(
        objects: &'scope [Object<'scope, 'image>],
        scratch: &'scope mut [usize],
    ) -> Result<Self, Error> {
        if objects.is_empty() || scratch.len() < objects.len() {
            return Err(Error::BufferTooSmall);
        }
        for (index, object) in objects.iter().enumerate() {
            if objects[..index]
                .iter()
                .any(|other| object.name == other.name)
            {
                return Err(Error::Invalid);
            }
            // The root's static TLS is described by its startup metadata.
            // A dependency TLS module needs the not-yet-implemented aggregate
            // layout/module allocator; never silently reuse the root's offsets.
            if index != 0
                && (0..object.image.count).any(|i| {
                    object
                        .image
                        .segment(i)
                        .is_ok_and(|s| s.kind == 7 && s.memory != 0)
                })
            {
                return Err(Error::Unsupported);
            }
            if object.bias % object.image.alignment() != 0 {
                return Err(Error::Invalid);
            }
            // The fixed container's metadata is also mapped. Reserve it along
            // with every LOAD when checking placement across objects.
            for range in ranges(object)? {
                if range.0 < USER_MIN || range.1 > USER_END {
                    return Err(Error::Invalid);
                }
                for other in &objects[..index] {
                    for previous in ranges(other)? {
                        if range.0 < previous.1 && previous.0 < range.1 {
                            return Err(Error::Invalid);
                        }
                    }
                }
            }
        }
        scratch[0] = 0;
        let mut length = 1;
        let mut cursor = 0;
        while cursor < length {
            objects[scratch[cursor]].image.dependencies(|name| {
                let index = objects
                    .iter()
                    .position(|object| object.name == name)
                    .ok_or(Error::Unsupported)?;
                if !scratch[..length].contains(&index) {
                    scratch[length] = index;
                    length += 1;
                }
                Ok(())
            })?;
            cursor += 1;
        }
        // Unreachable supplied images must not silently enter the global scope.
        if length != objects.len() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            objects,
            order: &scratch[..length],
        })
    }

    pub fn order(&self) -> &[usize] {
        self.order
    }

    fn resolve(&self, origin: usize, index: u32) -> Result<u64, Error> {
        let object = self.objects.get(origin).ok_or(Error::Invalid)?;
        let table = object.image.symbols.as_ref().ok_or(Error::Unsupported)?;
        let reference = table.entry(index)?;
        if reference.binding == 0 || reference.visibility != 0 || object.image.symbolic {
            if let Some(definition) = reference.definition {
                return object.image.definition_value(definition)?.at(object.bias);
            }
            if reference.visibility != 0 || reference.binding == 0 {
                return if reference.binding == 2 {
                    Ok(0)
                } else {
                    Err(Error::Unsupported)
                };
            }
        }
        for &candidate in self.order {
            let candidate = &self.objects[candidate];
            if let Some(table) = &candidate.image.symbols {
                if let Some(symbol) = table.find(reference.name)? {
                    if let Some(definition) = symbol.definition {
                        return candidate
                            .image
                            .definition_value(definition)?
                            .at(candidate.bias);
                    }
                }
            }
        }
        if reference.binding == 2 {
            Ok(0)
        } else {
            Err(Error::Unsupported)
        }
    }

    /// Prepare one object using the complete scope. The caller must install
    /// all members together; this does not itself map or execute any member.
    pub fn write(&self, index: usize, output: &mut [u8]) -> Result<usize, Error> {
        let object = self.objects.get(index).ok_or(Error::Invalid)?;
        object
            .image
            .write_resolved(object.bias, output, |symbol| self.resolve(index, symbol))
    }
}

fn ranges<'a>(object: &'a Object<'_, '_>) -> Result<impl Iterator<Item = (u64, u64)> + 'a, Error> {
    let image = object.image;
    // Validate all checked arithmetic before constructing the infallible view.
    let mut minimum = u64::MAX;
    for index in 0..image.count {
        let segment = image.segment(index)?;
        if segment.kind == LOAD && segment.memory != 0 {
            minimum = minimum.min(segment.address & !(PAGE - 1));
            page(add(add(segment.address, object.bias)?, segment.memory)?)?;
        }
    }
    let metadata = image.metadata_bytes()?;
    let base = add(minimum, object.bias)?
        .checked_sub(metadata)
        .ok_or(Error::Invalid)?;
    let metadata_end = add(base, metadata)?;
    Ok(
        core::iter::once((base, metadata_end)).chain((0..image.count).filter_map(move |index| {
            let segment = image.segment(index).ok()?;
            if segment.kind != LOAD || segment.memory == 0 {
                return None;
            }
            let start = (segment.address + object.bias) & !(PAGE - 1);
            let end = (segment.address + object.bias + segment.memory + PAGE - 1) & !(PAGE - 1);
            Some((start, end))
        })),
    )
}
