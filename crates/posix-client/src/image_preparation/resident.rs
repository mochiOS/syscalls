//! Owned, authenticated input graph for running-process library operations.
//! Reuses execution's discovery/search/capture and Resident's mapping/lifecycle.
//! No borrowed parser view survives an operation or requires lifetime erasure.
use super::*;
use crate::{
    elf_mapping,
    pie::{
        self,
        link_scope::{
            lookup::Version,
            resident::{Failure, Phase, State},
        },
    },
};

#[derive(Debug)]
pub enum Error<E> {
    Source(c_int),
    Elf(pie::Error),
    Resident(Failure<E>),
}

pub struct Library<B: Backend, M: elf_mapping::Backend, const N: usize> {
    state: State<M, N>,
    source: Buffer<B>,
    dependencies: dependencies::Dependencies<B>,
    output: Buffer<B>,
    callbacks: Buffer<B>,
    file: u32,
    address: u64,
    captured: bool,
}
impl<B: Backend, M: elf_mapping::Backend, const N: usize> Default for Library<B, M, N> {
    fn default() -> Self {
        Self {
            state: State::default(),
            source: Buffer::default(),
            dependencies: dependencies::Dependencies::default(),
            output: Buffer::default(),
            callbacks: Buffer::default(),
            file: 0,
            address: 0,
            captured: false,
        }
    }
}
impl<B: Backend, M: elf_mapping::Backend, const N: usize> Drop for Library<B, M, N> {
    fn drop(&mut self) {
        if self.file != 0 {
            B::critical(|| B::close(self.file));
        }
    }
}
impl<B: Backend, M: elf_mapping::Backend, const N: usize> Library<B, M, N> {
    pub fn phase(&self) -> Phase {
        self.state.phase()
    }
    pub fn retained(&self) -> usize {
        self.state.retained()
    }
    pub fn abandon(&mut self) {
        self.state.abandon();
    }
    pub fn source(&self) -> &[u8] {
        self.source.bytes()
    }

    /// Call only on a fresh, externally registered resource owner. All Handles
    /// and allocations are published before any blocking call or callback.
    /// Authentication of root and every dependency precedes any VM operation.
    pub fn open(
        &mut self,
        backend: &B,
        path: &[u8],
        variables: Environment<'_>,
        identity: crate::process_image::Identity,
        address: u64,
    ) -> Result<(), c_int> {
        if self.file != 0 || self.source.length != 0 || self.captured {
            return Err(EINVAL);
        }
        B::critical(|| {
            let file = backend.open_library(path)?;
            self.file = file.handle;
            if file.handle == 0
                || file.rights & posix_protocol::CHECK_EXECUTABLE_RIGHTS
                    != posix_protocol::CHECK_EXECUTABLE_RIGHTS
            {
                return Err(EACCES);
            }
            backend.validate_library(file)
        })?;
        self.source.capture(backend, self.file, MAX_IMAGE)?;
        backend.validate_captured(Source::Root, self.source.bytes())?;
        self.dependencies
            .discover(self.source.bytes(), backend, variables, identity, true)?;
        self.address = address;
        let scope = self.dependencies.scope(self.source.bytes(), address)?;
        self.state.bind(&scope).map_err(|_| ENOEXEC)?;
        let mut length = 0;
        for object in scope.objects() {
            length = length.max(object.image.output_length().map_err(|_| ENOEXEC)?);
        }
        self.output.reserve(length)?;
        self.output.length = length;
        self.callbacks
            .slots::<usize>(scope.lifecycle_scratch_len().map_err(|_| ENOEXEC)?)?;
        B::critical(|| {
            B::close(self.file);
            self.file = 0;
            self.captured = true;
        });
        Ok(())
    }
    pub fn install(&mut self, memory: impl FnMut() -> M) -> Result<(), Error<M::Error>> {
        if !self.captured {
            return Err(Error::Source(EINVAL));
        }
        let scope = self
            .dependencies
            .scope(self.source.bytes(), self.address)
            .map_err(Error::Source)?;
        let output =
            unsafe { core::slice::from_raw_parts_mut(self.output.pointer, self.output.length) };
        self.state
            .bind(&scope)
            .map_err(Error::Elf)?
            .install(output, memory)
            .map_err(Error::Resident)?;
        // Relocation scratch is never retained as live code or callback data.
        self.output = Buffer::default();
        Ok(())
    }
    pub fn initialize(
        &mut self,
        invoke: impl FnMut(u64) -> Result<(), M::Error>,
    ) -> Result<(), Error<M::Error>> {
        if !self.captured {
            return Err(Error::Source(EINVAL));
        }
        let scope = self
            .dependencies
            .scope(self.source.bytes(), self.address)
            .map_err(Error::Source)?;
        let scratch = unsafe {
            core::slice::from_raw_parts_mut(
                self.callbacks.pointer.cast::<usize>(),
                self.callbacks.length / core::mem::size_of::<usize>(),
            )
        };
        self.state
            .bind(&scope)
            .map_err(Error::Elf)?
            .initialize(scratch, invoke)
            .map_err(Error::Resident)
    }
    /// Raw numeric addresses, like dlsym results, are valid only while this
    /// library remains open. The embedding API owns those reference counts.
    pub fn symbol(&mut self, name: &[u8]) -> Result<Option<u64>, Error<M::Error>> {
        if !self.captured {
            return Err(Error::Source(EINVAL));
        }
        let scope = self
            .dependencies
            .scope(self.source.bytes(), self.address)
            .map_err(Error::Source)?;
        let loader = self.state.bind(&scope).map_err(Error::Elf)?;
        loader
            .symbol(name, Version::Default)
            .map(|symbol| symbol.map(|s| s.address()))
            .map_err(Error::Elf)
    }
    pub fn close(
        &mut self,
        invoke: impl FnMut(u64) -> Result<(), M::Error>,
    ) -> Result<(), Error<M::Error>> {
        if self.retained() == 0 {
            return Ok(());
        }
        let scope = self
            .dependencies
            .scope(self.source.bytes(), self.address)
            .map_err(Error::Source)?;
        let scratch = unsafe {
            core::slice::from_raw_parts_mut(
                self.callbacks.pointer.cast::<usize>(),
                self.callbacks.length / core::mem::size_of::<usize>(),
            )
        };
        self.state
            .bind(&scope)
            .map_err(Error::Elf)?
            .close(scratch, invoke)
            .map_err(Error::Resident)
    }
}
