//! Running-process library scope: relocate, map, initialize, borrow exports,
//! finalize and unmap as one owner. No filesystem or ambient authority is used.
//! The caller authenticates captured inputs before constructing the Scope and
//! retains this owner in its callback-abandonment chain before foreign calls.
use super::{
    Scope,
    lookup::{Export, Value, Version},
};
use crate::{
    elf_mapping::{self as vm, Backend, Installation, Mapping, Plan, Range},
    pie::Error as ElfError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Empty,
    Mapping,
    Mapped,
    Initializing,
    Ready,
    Finalizing,
    Failed,
    Closed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Operation<E> {
    State,
    Elf(ElfError),
    Image(crate::elf_launch::Error),
    Memory(vm::Error<E>),
    Callback(E),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Failure<E> {
    pub operation: Operation<E>,
    /// The original failure is preserved even when rollback also fails.
    pub cleanup: Option<E>,
}

pub struct Member<B: Backend> {
    mapping: Mapping<B>,
    initialized: bool,
}

enum PhaseSlot<'a> {
    Local(Phase),
    Shared(&'a mut Phase),
}

/// Persistent mapping ownership without references into parser workspaces.
/// A later borrowed view must describe exactly the same captured bytes, names,
/// placement and lookup order. No lifetime erasure or pinned self-reference is
/// needed. Store this owner before entering abandon-capable C callbacks.
pub struct State<B: Backend, const N: usize> {
    members: [Option<Member<B>>; N],
    phase: Phase,
    identity: Option<[u8; 32]>,
}
impl<B: Backend, const N: usize> Default for State<B, N> {
    fn default() -> Self {
        Self {
            members: [const { None }; N],
            phase: Phase::Empty,
            identity: None,
        }
    }
}
impl<B: Backend, const N: usize> State<B, N> {
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn retained(&self) -> usize {
        self.members
            .iter()
            .flatten()
            .filter(|m| m.mapping.retained().is_some())
            .count()
    }
    /// After a callback abandons its borrowed operation, prevent publication
    /// and allow explicit finalization/cleanup of the initialized prefix.
    pub fn abandon(&mut self) {
        if matches!(
            self.phase,
            Phase::Mapping | Phase::Initializing | Phase::Finalizing
        ) {
            self.phase = Phase::Failed;
        }
    }
    pub fn bind<'a, 'scope, 'image>(
        &'a mut self,
        scope: &'a Scope<'scope, 'image>,
    ) -> Result<Resident<'a, 'scope, 'image, B>, ElfError> {
        use sha2::{Digest, Sha256};
        if scope.objects.len() > N {
            return Err(ElfError::BufferTooSmall);
        }
        let mut digest = Sha256::new();
        digest.update(scope.external_lookup.map(|lookup| lookup as usize).unwrap_or(0).to_le_bytes());
        digest.update((scope.objects.len() as u64).to_le_bytes());
        for object in scope.objects {
            digest.update((object.name.len() as u64).to_le_bytes());
            digest.update(object.name);
            digest.update(object.bias.to_le_bytes());
            digest.update((object.image.bytes.len() as u64).to_le_bytes());
            digest.update(object.image.bytes);
        }
        for index in scope.order {
            digest.update((*index as u64).to_le_bytes());
        }
        let identity = digest.finalize().into();
        if let Some(previous) = self.identity {
            if previous != identity {
                return Err(ElfError::Invalid);
            }
        } else {
            validate(scope)?;
            self.identity = Some(identity);
        }
        Ok(Resident {
            scope,
            members: &mut self.members[..scope.objects.len()],
            phase: PhaseSlot::Shared(&mut self.phase),
        })
    }
}

fn validate(scope: &Scope<'_, '_>) -> Result<(), ElfError> {
    // Late TLS allocation and resolver startup need separate runtime
    // transactions. Reject before mapping, never publish unresolved code.
    for object in scope.objects {
        if object.image.is_fixed()
            || object.image.tls_template(0)?.is_some()
            || object.image.requires_indirect_scope()?
            || object.image.has_copies()?
            || object.image.lifecycle.preinit.count != 0
        {
            return Err(ElfError::Unsupported);
        }
    }
    Ok(())
}

/// Scratch slots belong to the caller; parsing and mapping require no global
/// allocator. A failed release retains the exact range for explicit retry.
pub struct Resident<'owner, 'scope, 'image, B: Backend> {
    scope: &'owner Scope<'scope, 'image>,
    members: &'owner mut [Option<Member<B>>],
    phase: PhaseSlot<'owner>,
}

impl<'owner, 'scope, 'image, B: Backend> Resident<'owner, 'scope, 'image, B> {
    pub fn new(
        scope: &'owner Scope<'scope, 'image>,
        members: &'owner mut [Option<Member<B>>],
    ) -> Result<Self, ElfError> {
        if members.len() != scope.objects.len() || members.iter().any(Option::is_some) {
            return Err(ElfError::Invalid);
        }
        validate(scope)?;
        Ok(Self {
            scope,
            members,
            phase: PhaseSlot::Local(Phase::Empty),
        })
    }
    pub fn phase(&self) -> Phase {
        match &self.phase {
            PhaseSlot::Local(phase) => *phase,
            PhaseSlot::Shared(phase) => **phase,
        }
    }
    fn set_phase(&mut self, value: Phase) {
        match &mut self.phase {
            PhaseSlot::Local(phase) => *phase = value,
            PhaseSlot::Shared(phase) => **phase = value,
        }
    }
    pub fn retained(&self) -> usize {
        self.members
            .iter()
            .flatten()
            .filter(|m| m.mapping.retained().is_some())
            .count()
    }
    fn failure(&mut self, operation: Operation<B::Error>, rollback: bool) -> Failure<B::Error> {
        self.set_phase(Phase::Failed);
        Failure {
            operation,
            cleanup: if rollback { self.release() } else { None },
        }
    }
    fn release(&mut self) -> Option<B::Error> {
        let mut first = None;
        for slot in self.members.iter_mut().rev() {
            if let Some(member) = slot {
                match member.mapping.release() {
                    Ok(()) => *slot = None,
                    Err(error) => {
                        if first.is_none() {
                            first = Some(error);
                        }
                    }
                }
            }
        }
        first
    }

    /// Reuse a single caller-owned output buffer for every relocation result.
    /// Nothing can look up symbols until all mappings and constructors finish.
    pub fn install(
        &mut self,
        output: &mut [u8],
        mut backend: impl FnMut() -> B,
    ) -> Result<(), Failure<B::Error>> {
        if self.phase() != Phase::Empty {
            return Err(Failure {
                operation: Operation::State,
                cleanup: None,
            });
        }
        if self
            .scope
            .objects
            .iter()
            .any(|object| object.image.output_length().is_ok_and(|n| n > output.len()))
        {
            return Err(Failure {
                operation: Operation::Elf(ElfError::BufferTooSmall),
                cleanup: None,
            });
        }
        self.set_phase(Phase::Mapping);
        for index in 0..self.scope.objects.len() {
            let result = (|| {
                let length = self.scope.write(index, output).map_err(Operation::Elf)?;
                let plan = Plan::new(&output[..length], 0).map_err(Operation::Image)?;
                let mut installation = Installation::new(backend());
                if let Err(error) = installation.stage(plan).and_then(|()| installation.seal()) {
                    if installation.retained().is_some() {
                        installation
                            .retain_failed(|mapping| {
                                self.members[index] = Some(Member {
                                    mapping,
                                    initialized: false,
                                });
                            })
                            .map_err(Operation::Memory)?;
                    }
                    return Err(Operation::Memory(error));
                }
                installation
                    .commit(|mapping| {
                        self.members[index] = Some(Member {
                            mapping,
                            initialized: false,
                        });
                    })
                    .map_err(Operation::Memory)?;
                Ok(())
            })();
            if let Err(error) = result {
                return Err(self.failure(error, true));
            }
        }
        // Eager relocation is complete, so RELRO precedes foreign callbacks.
        for (index, object) in self.scope.objects.iter().enumerate() {
            let mut memory_error = None;
            let result = object.image.relro(object.bias, |range| {
                // RELRO removes write access. It must preserve execute on an
                // originally readable/executable LOAD, rather than faulting
                // valid code when a linker includes it in a RELRO page.
                let mut executable = false;
                for header in 0..object.image.count {
                    let segment = object.image.segment(header)?;
                    if segment.kind == super::super::LOAD && segment.flags & 1 != 0 {
                        let start = (segment.address + object.bias) & !(super::super::PAGE - 1);
                        let end =
                            super::super::page(segment.address + object.bias + segment.memory)?;
                        executable |= start < range.address + range.length && range.address < end;
                    }
                }
                self.members[index]
                    .as_mut()
                    .unwrap()
                    .mapping
                    .relro(
                        Range {
                            address: range.address,
                            length: range.length,
                        },
                        executable,
                    )
                    .map_err(|error| {
                        memory_error = Some(error);
                        ElfError::Invalid
                    })
            });
            if let Err(error) = result {
                return Err(self.failure(
                    memory_error
                        .map(Operation::Memory)
                        .unwrap_or(Operation::Elf(error)),
                    true,
                ));
            }
        }
        self.set_phase(Phase::Mapped);
        Ok(())
    }

    fn call(
        lifecycle: &super::Lifecycle<'_, '_, '_>,
        address: u64,
        invoke: &mut impl FnMut(u64) -> Result<(), B::Error>,
    ) -> Result<(), Operation<B::Error>> {
        if address == 0 {
            return Ok(());
        }
        if !lifecycle.is_callable(address) {
            return Err(Operation::Elf(ElfError::Invalid));
        }
        invoke(address).map_err(Operation::Callback)
    }
    fn array(
        scope: &Scope<'_, '_>,
        lifecycle: &super::Lifecycle<'_, '_, '_>,
        origin: usize,
        address: u64,
        count: u64,
        reverse: bool,
        invoke: &mut impl FnMut(u64) -> Result<(), B::Error>,
    ) -> Result<(), Operation<B::Error>> {
        for at in 0..count {
            let index = if reverse { count - at - 1 } else { at };
            // Resolve from the immutable capture, not a live array which an
            // initializer or application could replace before dlclose.
            let object = &scope.objects[origin];
            let mut bytes = [0; 8];
            object
                .image
                .read_relocated(
                    address + index * 8,
                    &mut bytes,
                    object.bias,
                    |symbol, kind| scope.resolve(origin, symbol, kind),
                    |symbol, addend| scope.descriptor(origin, symbol, addend),
                )
                .map_err(Operation::Elf)?;
            let function = u64::from_le_bytes(bytes);
            // ELF init/fini arrays conventionally skip zero and -1 entries.
            if function != 0 && function != u64::MAX {
                Self::call(lifecycle, function, invoke)?;
            }
        }
        Ok(())
    }

    /// The runtime supplies its real callback boundary. Callback arrays are
    /// resolved from retained captured inputs, never reread from mutable LOADs.
    pub fn initialize(
        &mut self,
        scratch: &mut [usize],
        mut invoke: impl FnMut(u64) -> Result<(), B::Error>,
    ) -> Result<(), Failure<B::Error>> {
        if self.phase() != Phase::Mapped {
            return Err(Failure {
                operation: Operation::State,
                cleanup: None,
            });
        }
        let plan = self.scope.lifecycle(scratch).map_err(|error| Failure {
            operation: Operation::Elf(error),
            cleanup: None,
        })?;
        // Validate every captured init/fini pointer before running any code.
        // This also prevents a malformed later dependency from leaving an
        // earlier constructor's side effects behind during admission.
        for (index, object) in self.scope.objects.iter().enumerate() {
            for array in [
                object.image.lifecycle.initialize,
                object.image.lifecycle.finalize,
            ] {
                if let Err(error) = Self::array(
                    self.scope,
                    &plan,
                    index,
                    array.address,
                    array.count,
                    false,
                    &mut |_| Ok(()),
                ) {
                    return Err(self.failure(error, false));
                }
            }
        }
        self.set_phase(Phase::Initializing);
        for &index in plan.order() {
            let object = &self.scope.objects[index];
            let metadata = object.image.lifecycle;
            // If a callback reports failure after executing, close must still
            // retain the mappings and finalize this module at most once.
            self.members[index].as_mut().unwrap().initialized = true;
            let result = (|| {
                if metadata.init != 0 {
                    Self::call(&plan, metadata.init + object.bias, &mut invoke)?;
                }
                Self::array(
                    self.scope,
                    &plan,
                    index,
                    metadata.initialize.address,
                    metadata.initialize.count,
                    false,
                    &mut invoke,
                )
            })();
            if let Err(error) = result {
                return Err(self.failure(error, false));
            }
        }
        self.set_phase(Phase::Ready);
        Ok(())
    }

    pub fn symbol(
        &self,
        name: &[u8],
        version: Version<'_>,
    ) -> Result<Option<Symbol<'_, B>>, ElfError> {
        if self.phase() != Phase::Ready {
            return Err(ElfError::Invalid);
        }
        let Some(export) = self.scope.exports().find(name, version)? else {
            return Ok(None);
        };
        let Value::Address(address) = export.value else {
            return Err(ElfError::Unsupported);
        };
        let member = self.members[export.object]
            .as_ref()
            .ok_or(ElfError::Invalid)?;
        if !member.mapping.is_ready() {
            return Err(ElfError::Invalid);
        }
        Ok(Some(Symbol {
            export,
            address,
            _mapping: &member.mapping,
        }))
    }

    /// No lease returned by symbol() can remain borrowed across this call.
    /// Finalizers run before any member is unmapped, dependents first. A failed
    /// callback is never retried; failed VM cleanup remains explicitly owned.
    pub fn close(
        &mut self,
        scratch: &mut [usize],
        mut invoke: impl FnMut(u64) -> Result<(), B::Error>,
    ) -> Result<(), Failure<B::Error>> {
        if matches!(
            self.phase(),
            Phase::Empty | Phase::Closed | Phase::Mapping | Phase::Initializing | Phase::Finalizing
        ) {
            return Err(Failure {
                operation: Operation::State,
                cleanup: None,
            });
        }
        let plan = self.scope.lifecycle(scratch).map_err(|error| Failure {
            operation: Operation::Elf(error),
            cleanup: None,
        })?;
        self.set_phase(Phase::Finalizing);
        for &index in plan.order().iter().rev() {
            let Some(member) = self.members[index].as_mut() else {
                continue;
            };
            if !member.initialized {
                continue;
            }
            member.initialized = false;
            let object = &self.scope.objects[index];
            let metadata = object.image.lifecycle;
            let result = (|| {
                Self::array(
                    self.scope,
                    &plan,
                    index,
                    metadata.finalize.address,
                    metadata.finalize.count,
                    true,
                    &mut invoke,
                )?;
                if metadata.fini != 0 {
                    Self::call(&plan, metadata.fini + object.bias, &mut invoke)?;
                }
                Ok(())
            })();
            if let Err(error) = result {
                return Err(self.failure(error, false));
            }
        }
        if let Some(error) = self.release() {
            return Err(self.failure(Operation::Memory(vm::Error::Native(error)), false));
        }
        self.set_phase(Phase::Closed);
        Ok(())
    }
}

/// The selected module mapping stays borrowed for this symbol's lifetime.
/// Turning its address into a callable pointer remains the caller's unsafe ABI
/// responsibility; copied raw addresses must not outlive the library owner.
pub struct Symbol<'a, B: Backend> {
    pub export: Export,
    address: u64,
    _mapping: &'a Mapping<B>,
}
impl<B: Backend> Symbol<'_, B> {
    pub fn address(&self) -> u64 {
        self.address
    }
}
