//! Install captured, already-linked ELF LOAD bytes in the current process.
//! This owns a complete inaccessible reservation, populates RW/NX pages, then
//! seals LOAD permissions. Selection, authentication, relocation, RELRO and
//! constructor order remain with the userspace dynamic loader. No path opens.
use crate::elf_launch::{Error as ImageError, Image};
#[cfg(feature = "syscall-endpoint")]
pub mod native;
const PAGE: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub address: u64,
    pub length: u64,
}
#[derive(Clone, Copy)]
pub struct Plan<'a> {
    image: Image<'a>,
    bias: u64,
    range: Range,
}
impl<'a> Plan<'a> {
    /// The caller must retain an immutable authenticated capture and finish
    /// all ordinary relocations before installation. PT_INTERP requires the
    /// separate launch path; it is never silently ignored here. Entry zero is
    /// valid for shared objects. Sparse BSS remains demand-zero memory.
    pub fn new(bytes: &'a [u8], bias: u64) -> Result<Self, ImageError> {
        let image = Image::parse_mapping(bytes)?;
        if image.interpreter()?.is_some() {
            return Err(ImageError::Unsupported);
        }
        let (start, end) = image.mapping_range(bias)?;
        Ok(Self {
            image,
            bias,
            range: Range {
                address: start,
                length: end - start,
            },
        })
    }
    pub fn range(&self) -> Range {
        self.range
    }
}

/// Explicit VM mechanisms, not path or execution policy. Reserve must atomically
/// acquire the exact complete range or leave it unchanged. Populate replaces
/// only a subrange of that owned reservation with fresh zero-filled RW/NX
/// pages. Failed populate/protect may be partial; release covers the whole
/// reservation, including holes and attempted ranges. No operation may create
/// W+X. Callers retain the owner through callbacks and defer frame abandonment
/// during acquisition/publication and release with `critical`.
pub trait Backend {
    type Error;
    fn critical<T>(operation: impl FnOnce() -> T) -> T;
    fn reserve(&self, range: Range) -> Result<(), Self::Error>;
    fn populate(&self, range: Range) -> Result<(), Self::Error>;
    fn write(&self, address: u64, bytes: &[u8]) -> Result<(), Self::Error>;
    /// access uses the generic mnu MEMORY_ACCESS bits.
    fn protect(&self, range: Range, access: u64) -> Result<(), Self::Error>;
    fn release(&self, range: Range) -> Result<(), Self::Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Empty,
    Staging,
    Staged,
    Sealing,
    Sealed,
    Failed,
    Closed,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    State,
    Native(E),
    Cleanup { operation: E, release: E },
}

pub struct Installation<'a, B: Backend> {
    backend: Option<B>,
    plan: Option<Plan<'a>>,
    retained: bool,
    phase: Phase,
}
impl<'a, B: Backend> Installation<'a, B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend: Some(backend),
            plan: None,
            retained: false,
            phase: Phase::Empty,
        }
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    fn backend(&self) -> &B {
        self.backend.as_ref().unwrap()
    }
    pub fn retained(&self) -> Option<Range> {
        self.retained.then(|| self.plan.unwrap().range)
    }
    fn abort(&mut self, operation: B::Error) -> Error<B::Error> {
        self.phase = Phase::Failed;
        if self.retained {
            let range = self.plan.unwrap().range;
            match B::critical(|| {
                self.backend().release(range)?;
                self.retained = false;
                Ok(())
            }) {
                Ok(()) => (),
                Err(release) => return Error::Cleanup { operation, release },
            }
        }
        Error::Native(operation)
    }
    pub fn stage(&mut self, plan: Plan<'a>) -> Result<(), Error<B::Error>> {
        if self.phase != Phase::Empty {
            return Err(Error::State);
        }
        self.phase = Phase::Staging;
        self.plan = Some(plan);
        if let Err(e) = B::critical(|| {
            self.backend().reserve(plan.range)?;
            self.retained = true;
            Ok(())
        }) {
            return Err(self.abort(e));
        }
        for index in 0..plan.image.count() {
            let segment = plan.image.segment(index);
            if segment.kind != 1 || segment.memory == 0 {
                continue;
            }
            let address = plan.bias + segment.address;
            let start = address & !(PAGE - 1);
            let end = (address + segment.memory + PAGE - 1) & !(PAGE - 1);
            let range = Range {
                address: start,
                length: end - start,
            };
            if let Err(e) = self.backend().populate(range) {
                return Err(self.abort(e));
            }
            if segment.file != 0 {
                if let Err(e) = self.backend().write(address, plan.image.bytes(segment)) {
                    return Err(self.abort(e));
                }
            }
        }
        self.phase = Phase::Staged;
        Ok(())
    }
    /// Publish executable permissions only after every LOAD has been populated.
    /// A partial native protection failure releases the entire installation;
    /// constructors/resolvers must never run unless this succeeds. RELRO is a
    /// separate loader step after its remaining fixups have completed.
    pub fn seal(&mut self) -> Result<(), Error<B::Error>> {
        if self.phase != Phase::Staged {
            return Err(Error::State);
        }
        self.phase = Phase::Sealing;
        let plan = self.plan.unwrap();
        for index in 0..plan.image.count() {
            let segment = plan.image.segment(index);
            if segment.kind != 1 || segment.memory == 0 {
                continue;
            }
            let address = plan.bias + segment.address;
            let start = address & !(PAGE - 1);
            let end = (address + segment.memory + PAGE - 1) & !(PAGE - 1);
            let access =
                u64::from((segment.flags & 4) >> 2 | segment.flags & 2 | (segment.flags & 1) << 2);
            if let Err(e) = self.backend().protect(
                Range {
                    address: start,
                    length: end - start,
                },
                access,
            ) {
                return Err(self.abort(e));
            }
        }
        self.phase = Phase::Sealed;
        Ok(())
    }
    /// Publish a sealed, independently owned mapping before callbacks resume.
    /// The destination must retain this owner; do not invoke application code
    /// in the publication closure. After commit this transaction is closed and
    /// may be dropped together with all source/prepared bytes. No lifetime
    /// erasure, leaked input buffer or self-referential module is needed.
    pub fn commit(&mut self, publish: impl FnOnce(Mapping<B>)) -> Result<(), Error<B::Error>> {
        if self.phase != Phase::Sealed {
            return Err(Error::State);
        }
        B::critical(|| {
            let mapping = Mapping {
                backend: self.backend.take().unwrap(),
                range: Some(self.plan.unwrap().range),
                ready: true,
            };
            self.retained = false;
            self.phase = Phase::Closed;
            publish(mapping);
        });
        Ok(())
    }
    /// Release before discarding the owner when cleanup errors must be handled.
    /// Failure retains the range for another explicit cleanup attempt. A used
    /// installation can never be staged again, even after successful release.
    pub fn release(&mut self) -> Result<(), B::Error> {
        if self.retained {
            self.phase = Phase::Failed;
            let range = self.plan.unwrap().range;
            B::critical(|| {
                self.backend().release(range)?;
                self.retained = false;
                Ok(())
            })?;
        }
        self.phase = Phase::Closed;
        Ok(())
    }
}
impl<B: Backend> Drop for Installation<'_, B> {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

/// Installed LOADs without a borrow of parser/captured file storage. A loader
/// keeps this owner until all library users and finalizers have finished.
pub struct Mapping<B: Backend> {
    backend: B,
    range: Option<Range>,
    ready: bool,
}
impl<B: Backend> Mapping<B> {
    pub fn retained(&self) -> Option<Range> {
        self.range
    }
    pub fn is_ready(&self) -> bool {
        self.ready
    }
    /// A failed native unmap may be partial: revoke ready state and retain the
    /// range for cleanup. Drop is best effort; handle this result explicitly
    /// when the loader must report a release failure.
    pub fn release(&mut self) -> Result<(), B::Error> {
        self.ready = false;
        if let Some(range) = self.range {
            B::critical(|| {
                self.backend.release(range)?;
                self.range = None;
                Ok(())
            })?;
        }
        Ok(())
    }
}
impl<B: Backend> Drop for Mapping<B> {
    fn drop(&mut self) {
        let _ = self.release();
    }
}
