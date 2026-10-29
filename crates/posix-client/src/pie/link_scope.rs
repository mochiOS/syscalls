//! Explicit, borrowed link scope. Filesystem discovery, Handle acquisition and
//! execution authority remain the caller's responsibility; no path is opened.
use super::{Error, LOAD, PAGE, Pie, USER_END, USER_MIN, add, page};

mod bundle;
mod lifecycle;
mod indirect;
pub use lifecycle::{Lifecycle, Step};
pub use indirect::Deferred;

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
            if index != 0 && object.image.has_copies()? {
                return Err(Error::Invalid);
            }
            if object.image.is_fixed() && (index != 0 || object.bias != 0) {
                return Err(Error::Invalid);
            }
            if objects[..index]
                .iter()
                .any(|other| object.name == other.name)
            {
                return Err(Error::Invalid);
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
        // Check all recorded ABI requirements, including nodes not referenced
        // by an eager relocation. No image is emitted before this succeeds.
        for object in objects {
            if let Some(table) = &object.image.symbols {
                table.requirements(|file, name, hash, weak| {
                    let mut provider = None;
                    for &index in &scratch[..length] {
                        let candidate = &objects[index];
                        if candidate.name == file || candidate.image.soname()? == Some(file) {
                            provider = Some(candidate);
                            break;
                        }
                    }
                    let provider = provider.ok_or(Error::Invalid)?;
                    let available = provider.image.symbols.as_ref().ok_or(Error::Invalid)?;
                    if !available.provides(name, hash)? && !weak {
                        return Err(Error::Unsupported);
                    }
                    Ok(())
                })?;
            }
        }
        let scope = Self {
            objects,
            order: &scratch[..length],
        };
        objects[0].image.relocations(|_, value| {
            if let super::Value::Copy { index, .. } = value {
                scope.copy_source(index)?;
            }
            Ok(())
        })?;
        Ok(scope)
    }

    pub fn order(&self) -> &[usize] {
        self.order
    }

    fn definition(
        &self,
        origin: usize,
        index: u32,
    ) -> Result<Option<(usize, super::symbols::Definition, u64)>, Error> {
        let object = self.objects.get(origin).ok_or(Error::Invalid)?;
        let table = object.image.symbols.as_ref().ok_or(Error::Unsupported)?;
        let reference = table.entry(index)?;
        if reference.binding == 0
            || reference.visibility != 0
            || matches!(reference.version, super::symbols::Version::Local)
            || object.image.symbolic
        {
            if let Some(definition) = reference.definition {
                return Ok(Some((origin, definition, reference.size)));
            }
            if reference.visibility != 0
                || reference.binding == 0
                || matches!(reference.version, super::symbols::Version::Local)
            {
                return if reference.binding == 2 {
                    Ok(None)
                } else {
                    Err(Error::Unsupported)
                };
            }
        }
        for &candidate in self.order {
            if let Some(table) = &self.objects[candidate].image.symbols {
                if let Some(symbol) = table.find_versioned(reference.name, reference.version)? {
                    if let Some(definition) = symbol.definition {
                        return Ok(Some((candidate, definition, symbol.size)));
                    }
                }
            }
        }
        if reference.binding == 2 {
            Ok(None)
        } else {
            Err(Error::Unsupported)
        }
    }
    fn resolve(&self, origin: usize, index: u32, kind: u32) -> Result<u64, Error> {
        // Z is the selected definition's size, with the same binding/version
        // rules as addresses. A placement bias is never part of this value.
        if matches!(kind, 32 | 33) {
            return self
                .definition(origin, index)?
                .map_or(Ok(0), |(object, definition, size)| {
                    self.objects[object].image.definition_size(definition, size)
                });
        }
        if kind == 0 {
            return self
                .definition(origin, index)?
                .map_or(Ok(0), |(index, definition, _)| {
                    let object = &self.objects[index];
                    object.image.definition_value(definition)?.at(object.bias)
                });
        }
        let (object, offset) = if index == 0 {
            (origin, 0)
        } else {
            let (object, definition, _) =
                self.definition(origin, index)?.ok_or(Error::Unsupported)?;
            (
                object,
                self.objects[object].image.tls_definition(definition)?,
            )
        };
        self.objects[object]
            .image
            .tls_template(0)?
            .ok_or(Error::Invalid)?;
        match kind {
            16 => Ok((object + 1) as u64),
            17 => Ok(offset),
            18 => {
                let mut distance = 0;
                for member in &self.objects[..=object] {
                    if let Some(template) = member.image.tls_template(0)? {
                        distance = crate::static_tls::distance_after(distance, template)
                            .ok_or(Error::Overflow)?;
                    }
                }
                i64::try_from(distance).map_err(|_| Error::Overflow)?;
                Ok(offset.wrapping_sub(distance as u64))
            }
            _ => Err(Error::Unsupported),
        }
    }
    fn descriptor(&self, origin: usize, index: u32, addend: u64) -> Result<(u64, u64), Error> {
        let missing = index != 0 && self.definition(origin, index)?.is_none();
        let name = if missing {
            b"__mochios_tlsdesc_weak".as_slice()
        } else {
            b"__mochios_tlsdesc_static".as_slice()
        };
        let root = &self.objects[0];
        let function = root
            .image
            .runtime_function(name)?
            .ok_or(Error::Unsupported)?;
        let argument = if missing {
            addend
        } else {
            self.resolve(origin, index, 18)?.wrapping_add(addend)
        };
        Ok((add(root.bias, function)?, argument))
    }

    fn copy_source(&self, index: u32) -> Result<Option<(usize, u64, u64)>, Error> {
        let root = self.objects[0]
            .image
            .symbols
            .as_ref()
            .ok_or(Error::Invalid)?;
        let reference = root.entry(index)?;
        let Some(super::symbols::Definition::Image {
            size: destination_size,
            ..
        }) = reference.definition
        else {
            return Err(Error::Invalid);
        };
        // COPY locates the external initializer, while all ordinary references
        // still resolve to the root's canonical destination.
        for &candidate in &self.order[1..] {
            if let Some(table) = &self.objects[candidate].image.symbols {
                if let Some(symbol) = table.find_versioned(reference.name, reference.version)? {
                    let Some(super::symbols::Definition::Image { value, size }) = symbol.definition
                    else {
                        return Err(Error::Invalid);
                    };
                    if !matches!(symbol.kind, 0 | 1) || symbol.visibility != 0 {
                        return Err(Error::Unsupported);
                    }
                    self.objects[candidate]
                        .image
                        .definition_value(super::symbols::Definition::Image { value, size })?;
                    return Ok(Some((candidate, value, size.min(destination_size))));
                }
            }
        }
        if reference.binding == 2 {
            Ok(None)
        } else {
            Err(Error::Unsupported)
        }
    }

    fn copy(&self, origin: usize, index: u32, output: &mut [u8]) -> Result<(), Error> {
        if origin != 0 {
            return Err(Error::Invalid);
        }
        let Some((provider, address, length)) = self.copy_source(index)? else {
            return Ok(());
        };
        let object = &self.objects[provider];
        let length = usize::try_from(length).map_err(|_| Error::Overflow)?;
        object.image.read_relocated(
            address,
            output.get_mut(..length).ok_or(Error::BufferTooSmall)?,
            object.bias,
            |symbol, kind| self.resolve(provider, symbol, kind),
            |symbol, addend| self.descriptor(provider, symbol, addend),
        )
    }

    /// Prepare one object using the complete scope. The caller must install
    /// all members together; this does not itself map or execute any member.
    pub fn write(&self, index: usize, output: &mut [u8]) -> Result<usize, Error> {
        self.write_with_deferred(index, output, false, false)
    }
    fn write_with_deferred(
        &self,
        index: usize,
        output: &mut [u8],
        deferred: bool,
        copies: bool,
    ) -> Result<usize, Error> {
        let object = self.objects.get(index).ok_or(Error::Invalid)?;
        object.image.write_resolved(
            object.bias,
            output,
            |symbol, kind| self.resolve(index, symbol, kind),
            |symbol, addend| self.descriptor(index, symbol, addend),
            |symbol, output| self.copy(index, symbol, output),
            |target, value| {
                if copies && matches!(value, super::Value::Copy { .. }) {
                    return Ok(true);
                }
                if deferred {
                    Ok(self.indirect_fixup(index, target, value)?.is_some())
                } else {
                    Ok(false)
                }
            },
        )
    }
}

fn ranges<'a>(object: &'a Object<'_, '_>) -> Result<impl Iterator<Item = (u64, u64)> + 'a, Error> {
    let image = object.image;
    // Validate all checked arithmetic before constructing the infallible view.
    for index in 0..image.count {
        let segment = image.segment(index)?;
        if segment.kind == LOAD && segment.memory != 0 {
            page(add(add(segment.address, object.bias)?, segment.memory)?)?;
        }
    }
    let metadata = image.metadata_bytes()?;
    let base = image.metadata_address(object.bias)?;
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
