pub const FD_CLOEXEC: u32 = 1;
pub const DEFAULT_FD_LIMIT: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<H> {
    pub handle: H,
    pub rights: u64,
    pub descriptor_flags: u32,
}

pub trait HandleOps<H> {
    type Error;

    /// Clones a reference to the same underlying open-file description.
    fn clone_handle(&mut self, handle: H, rights: u64) -> Result<H, Self::Error>;
    fn close_handle(&mut self, handle: H);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeekBasis {
    Start,
    Current,
    End,
}

/// Fast-path operations on an already resolved kernel object.
///
/// Implementations receive the object handle, never the process-local POSIX
/// descriptor number.
pub trait FileOps<H> {
    type Error;

    fn read(&mut self, handle: H, buffer: &mut [u8]) -> Result<usize, Self::Error>;
    fn write(&mut self, handle: H, buffer: &[u8]) -> Result<usize, Self::Error>;
    fn seek(&mut self, handle: H, offset: i64, basis: SeekBasis) -> Result<u64, Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdError<E> {
    BadDescriptor,
    InvalidDescriptor,
    Handle(E),
}

#[derive(Clone, Debug)]
pub struct FdTable<H> {
    entries: [Option<Entry<H>>; DEFAULT_FD_LIMIT],
}

impl<H: Copy> FdTable<H> {
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; DEFAULT_FD_LIMIT],
        }
    }

    pub fn get(&self, fd: i32) -> Option<Entry<H>> {
        let index = usize::try_from(fd).ok()?;
        self.entries.get(index).copied().flatten()
    }

    pub fn get_mut(&mut self, fd: i32) -> Option<&mut Entry<H>> {
        let index = usize::try_from(fd).ok()?;
        self.entries.get_mut(index)?.as_mut()
    }

    pub fn install(&mut self, entry: Entry<H>) -> Result<i32, FdError<core::convert::Infallible>> {
        if let Some((index, slot)) = self
            .entries
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
        {
            *slot = Some(entry);
            return i32::try_from(index).map_err(|_| FdError::InvalidDescriptor);
        }
        Err(FdError::InvalidDescriptor)
    }

    /// Installs a descriptor in the first free slot within `[minimum, limit)`.
    ///
    /// Resource-limit policy remains in the caller; this table only enforces
    /// the supplied process-local descriptor range.
    pub fn install_from(
        &mut self,
        minimum: i32,
        limit: i32,
        entry: Entry<H>,
    ) -> Result<i32, FdError<core::convert::Infallible>> {
        let minimum = usize::try_from(minimum).map_err(|_| FdError::InvalidDescriptor)?;
        let limit = usize::try_from(limit).map_err(|_| FdError::InvalidDescriptor)?;
        if minimum >= limit || limit > DEFAULT_FD_LIMIT || limit > i32::MAX as usize {
            return Err(FdError::InvalidDescriptor);
        }
        if let Some(index) = (minimum..limit).find(|index| self.entries[*index].is_none()) {
            self.entries[index] = Some(entry);
            return Ok(index as i32);
        }
        Err(FdError::InvalidDescriptor)
    }

    pub fn install_at<O: HandleOps<H>>(
        &mut self,
        fd: i32,
        entry: Entry<H>,
        operations: &mut O,
    ) -> Result<(), FdError<O::Error>> {
        let index = usize::try_from(fd).map_err(|_| FdError::InvalidDescriptor)?;
        if index >= DEFAULT_FD_LIMIT {
            return Err(FdError::InvalidDescriptor);
        }
        if let Some(replaced) = self.entries[index].replace(entry) {
            operations.close_handle(replaced.handle);
        }
        Ok(())
    }

    pub fn set_descriptor_flags(&mut self, fd: i32, flags: u32) -> Result<(), FdError<()>> {
        let index = usize::try_from(fd).map_err(|_| FdError::BadDescriptor)?;
        let entry = self
            .entries
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(FdError::BadDescriptor)?;
        entry.descriptor_flags = flags;
        Ok(())
    }

    pub fn take(&mut self, fd: i32) -> Result<Entry<H>, FdError<()>> {
        let index = usize::try_from(fd).map_err(|_| FdError::BadDescriptor)?;
        self.entries
            .get_mut(index)
            .and_then(Option::take)
            .ok_or(FdError::BadDescriptor)
    }

    pub fn close<O: HandleOps<H>>(
        &mut self,
        fd: i32,
        operations: &mut O,
    ) -> Result<(), FdError<O::Error>> {
        let index = usize::try_from(fd).map_err(|_| FdError::BadDescriptor)?;
        let entry = self
            .entries
            .get_mut(index)
            .and_then(Option::take)
            .ok_or(FdError::BadDescriptor)?;
        operations.close_handle(entry.handle);
        Ok(())
    }

    pub fn read<O: FileOps<H>>(
        &self,
        fd: i32,
        buffer: &mut [u8],
        operations: &mut O,
    ) -> Result<usize, FdError<O::Error>> {
        let entry = self.get(fd).ok_or(FdError::BadDescriptor)?;
        operations
            .read(entry.handle, buffer)
            .map_err(FdError::Handle)
    }

    pub fn write<O: FileOps<H>>(
        &self,
        fd: i32,
        buffer: &[u8],
        operations: &mut O,
    ) -> Result<usize, FdError<O::Error>> {
        let entry = self.get(fd).ok_or(FdError::BadDescriptor)?;
        operations
            .write(entry.handle, buffer)
            .map_err(FdError::Handle)
    }

    pub fn seek<O: FileOps<H>>(
        &self,
        fd: i32,
        offset: i64,
        basis: SeekBasis,
        operations: &mut O,
    ) -> Result<u64, FdError<O::Error>> {
        let entry = self.get(fd).ok_or(FdError::BadDescriptor)?;
        operations
            .seek(entry.handle, offset, basis)
            .map_err(FdError::Handle)
    }

    pub fn duplicate<O: HandleOps<H>>(
        &mut self,
        fd: i32,
        operations: &mut O,
    ) -> Result<i32, FdError<O::Error>> {
        let source = self.get(fd).ok_or(FdError::BadDescriptor)?;
        let handle = operations
            .clone_handle(source.handle, source.rights)
            .map_err(FdError::Handle)?;
        self.install_typed(Entry {
            handle,
            rights: source.rights,
            descriptor_flags: source.descriptor_flags & !FD_CLOEXEC,
        })
    }

    pub fn duplicate_to<O: HandleOps<H>>(
        &mut self,
        source_fd: i32,
        target_fd: i32,
        operations: &mut O,
    ) -> Result<i32, FdError<O::Error>> {
        if target_fd < 0 {
            return Err(FdError::InvalidDescriptor);
        }
        if source_fd == target_fd {
            self.get(source_fd).ok_or(FdError::BadDescriptor)?;
            return Ok(target_fd);
        }
        let source = self.get(source_fd).ok_or(FdError::BadDescriptor)?;
        let handle = operations
            .clone_handle(source.handle, source.rights)
            .map_err(FdError::Handle)?;
        let target_index = target_fd as usize;
        if target_index >= DEFAULT_FD_LIMIT {
            return Err(FdError::InvalidDescriptor);
        }
        if let Some(replaced) = self.entries[target_index].replace(Entry {
            handle,
            rights: source.rights,
            descriptor_flags: source.descriptor_flags & !FD_CLOEXEC,
        }) {
            operations.close_handle(replaced.handle);
        }
        Ok(target_fd)
    }

    pub fn close_on_exec<O: HandleOps<H>>(&mut self, operations: &mut O) {
        for slot in &mut self.entries {
            if slot
                .as_ref()
                .is_some_and(|entry| entry.descriptor_flags & FD_CLOEXEC != 0)
                && let Some(entry) = slot.take()
            {
                operations.close_handle(entry.handle);
            }
        }
    }

    pub fn inherited(&self) -> impl Iterator<Item = (i32, Entry<H>)> + '_ {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let entry = (*entry)?;
                (entry.descriptor_flags & FD_CLOEXEC == 0)
                    .then(|| i32::try_from(index).ok().map(|fd| (fd, entry)))
                    .flatten()
            })
    }

    fn install_typed<E>(&mut self, entry: Entry<H>) -> Result<i32, FdError<E>> {
        if let Some((index, slot)) = self
            .entries
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.is_none())
        {
            *slot = Some(entry);
            return i32::try_from(index).map_err(|_| FdError::InvalidDescriptor);
        }
        Err(FdError::InvalidDescriptor)
    }
}

impl<H: Copy> Default for FdTable<H> {
    fn default() -> Self {
        Self::new()
    }
}
