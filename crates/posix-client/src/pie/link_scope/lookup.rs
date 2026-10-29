//! Named exports for dlsym/dlvsym. No mapping, symbol execution, TLS allocation
//! or process-global namespace state lives here. The loader supplies a pinned
//! visible object set/order and keeps selected mappings alive during resolve.
use super::super::{Error, USER_END, USER_MIN, symbols::Definition};
use super::{Object, Scope, ranges};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version<'a> {
    Default,
    Named(&'a [u8]),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    Address(u64),
    /// Offset in this provider's PT_TLS, not a process-global TLS module ID.
    Tls {
        offset: u64,
    },
    /// The caller must invoke the resolver after mapping/TLS initialization.
    Ifunc {
        resolver: u64,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Export {
    pub object: usize,
    pub size: u64,
    pub value: Value,
}
impl Export {
    /// Resolve thread-dependent or indirect values in caller-supplied context.
    /// An address/resolver result of zero is successful. Missing exports are
    /// represented by lookup's None, independently of callback errors.
    pub fn resolve<E>(
        self,
        mut tls: impl FnMut(usize, u64) -> Result<u64, E>,
        mut ifunc: impl FnMut(usize, u64) -> Result<u64, E>,
    ) -> Result<u64, E> {
        match self.value {
            Value::Address(value) => Ok(value),
            Value::Tls { offset } => tls(self.object, offset),
            Value::Ifunc { resolver } => ifunc(self.object, resolver),
        }
    }
}
pub struct Search<'scope, 'image> {
    objects: &'scope [Object<'scope, 'image>],
    order: &'scope [usize],
}
impl<'scope, 'image> Search<'scope, 'image> {
    /// Explicit visible scope: global/local namespace policy belongs to the
    /// loader. Unlisted objects cannot satisfy this lookup. Duplicate or invalid
    /// indices, impossible biases and invalid placements are rejected upfront.
    pub fn new(
        objects: &'scope [Object<'scope, 'image>],
        order: &'scope [usize],
    ) -> Result<Self, Error> {
        for (at, &index) in order.iter().enumerate() {
            let object = objects.get(index).ok_or(Error::Invalid)?;
            if order[..at].contains(&index)
                || object.bias % object.image.alignment() != 0
                || (object.image.is_fixed() && object.bias != 0)
            {
                return Err(Error::Invalid);
            }
            for (start, end) in ranges(object)? {
                if start < USER_MIN || end > USER_END {
                    return Err(Error::Invalid);
                }
            }
        }
        Ok(Self { objects, order })
    }
    /// A dlopen handle's dependency family, rooted at any captured object.
    /// Derive breadth-first order, excluding unrelated global/local objects and
    /// deduplicating cycles. Missing or ambiguous DT_NEEDED inputs are errors;
    /// this never opens an ambient path or silently expands the visible scope.
    pub fn family(
        objects: &'scope [Object<'scope, 'image>],
        root: usize,
        scratch: &'scope mut [usize],
    ) -> Result<Self, Error> {
        if root >= objects.len() {
            return Err(Error::Invalid);
        }
        if scratch.len() < objects.len() {
            return Err(Error::BufferTooSmall);
        }
        scratch[0] = root;
        let mut length = 1;
        let mut cursor = 0;
        while cursor < length {
            objects[scratch[cursor]].image.dependencies(|name| {
                let mut matches = objects
                    .iter()
                    .enumerate()
                    .filter(|(_, object)| object.name == name);
                let (index, _) = matches.next().ok_or(Error::Unsupported)?;
                if matches.next().is_some() {
                    return Err(Error::Invalid);
                }
                if !scratch[..length].contains(&index) {
                    scratch[length] = index;
                    length += 1;
                }
                Ok(())
            })?;
            cursor += 1;
        }
        Self::new(objects, &scratch[..length])
    }
    pub fn order(&self) -> &[usize] {
        self.order
    }
    pub fn find(&self, name: &[u8], version: Version<'_>) -> Result<Option<Export>, Error> {
        self.find_in(self.order, name, version)
    }
    /// RTLD_NEXT's search boundary, within a caller-selected visible scope.
    /// The caller must identify its module from trusted local loader metadata;
    /// an origin outside this scope is rejected rather than restarting at zero.
    pub fn after(
        &self,
        origin: usize,
        name: &[u8],
        version: Version<'_>,
    ) -> Result<Option<Export>, Error> {
        let at = self
            .order
            .iter()
            .position(|&index| index == origin)
            .ok_or(Error::Invalid)?;
        self.find_in(&self.order[at + 1..], name, version)
    }
    fn find_in(
        &self,
        order: &[usize],
        name: &[u8],
        version: Version<'_>,
    ) -> Result<Option<Export>, Error> {
        let version = match version {
            Version::Default => None,
            Version::Named(v) => Some(v),
        };
        if name.contains(&0) || version.is_some_and(|v| v.contains(&0)) {
            return Err(Error::Invalid);
        }
        for &index in order {
            let object = &self.objects[index];
            let Some(table) = &object.image.symbols else {
                continue;
            };
            let Some(entry) = table.find_export(name, version)? else {
                continue;
            };
            let definition = entry.definition.ok_or(Error::Invalid)?;
            let value = match definition {
                Definition::Tls { .. } => Value::Tls {
                    offset: object.image.tls_definition(definition)?,
                },
                Definition::Indirect { .. } => Value::Ifunc {
                    resolver: object.image.resolver_address(definition, object.bias)?,
                },
                _ => Value::Address(object.image.definition_value(definition)?.at(object.bias)?),
            };
            return Ok(Some(Export {
                object: index,
                size: entry.size,
                value,
            }));
        }
        Ok(None)
    }
}
impl<'scope, 'image> Scope<'scope, 'image> {
    /// Named exports in this scope's established dependency/search order.
    pub fn exports(&self) -> Search<'_, 'image> {
        Search {
            objects: self.objects,
            order: self.order,
        }
    }
}
