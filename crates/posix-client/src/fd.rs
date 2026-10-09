pub const FD_CLOEXEC: u32 = 1;
pub const DEFAULT_FD_LIMIT: usize = 256;

/// POSIX descriptor access-mode checks belong above native Handle rights.
/// A denied descriptor operation reports EBADF without issuing native I/O;
/// allowed operations still require the kernel's independent rights check.
pub const fn access_allows_read(open_flags: u32) -> bool {
    matches!(open_flags & 3, 0 | 2)
}

pub const fn access_allows_write(open_flags: u32) -> bool {
    matches!(open_flags & 3, 1 | 2)
}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchFdDescription {
    pub kind: u8,
    pub open_flags: u32,
    pub has_handle: bool,
}

pub trait LaunchContextOps<H> {
    type Error;

    fn get_value(&mut self, key: u64) -> Result<Option<u64>, Self::Error>;
    fn get_handle(&mut self, key: u64) -> Result<Option<H>, Self::Error>;
    fn get_handle_rights(&mut self, handle: H) -> Result<u64, Self::Error>;
    fn set_value(&mut self, key: u64, value: u64) -> Result<(), Self::Error>;
    fn remove_value(&mut self, key: u64) -> Result<(), Self::Error>;
    fn set_handle(&mut self, key: u64, handle: H) -> Result<(), Self::Error>;
    fn remove_handle(&mut self, key: u64) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchFdError<E> {
    Context(E),
    InvalidDescriptor,
    InvalidMetadata,
    MissingHandle,
    UnexpectedHandle,
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

    /// Applies the close operation required by `posix_spawn` file actions.
    ///
    /// POSIX requires this action to succeed when the descriptor is already
    /// closed, unlike the public `close(2)` operation.
    pub fn close_for_spawn<O: HandleOps<H>>(&mut self, fd: i32, operations: &mut O) {
        if self.get(fd).is_some() {
            let _ = self.close(fd, operations);
        }
    }

    /// Applies the descriptor duplication required by `posix_spawn`.
    ///
    /// The destination's close-on-exec flag is always cleared, including the
    /// `source_fd == target_fd` case where ordinary `dup2` leaves it intact.
    pub fn duplicate_for_spawn<O: HandleOps<H>>(
        &mut self,
        source_fd: i32,
        target_fd: i32,
        operations: &mut O,
    ) -> Result<i32, FdError<O::Error>> {
        let target_fd = self.duplicate_to(source_fd, target_fd, operations)?;
        let target = self.get_mut(target_fd).ok_or(FdError::InvalidDescriptor)?;
        target.descriptor_flags &= !FD_CLOEXEC;
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

pub fn stage_launch_context<H, C, D>(
    table: &FdTable<H>,
    descriptor_limit: usize,
    context: &mut C,
    mut describe: D,
) -> Result<(), LaunchFdError<C::Error>>
where
    H: Copy,
    C: LaunchContextOps<H>,
    D: FnMut(H) -> Option<LaunchFdDescription>,
{
    if descriptor_limit > DEFAULT_FD_LIMIT || descriptor_limit > i32::MAX as usize {
        return Err(LaunchFdError::InvalidDescriptor);
    }
    for index in 0..descriptor_limit {
        let fd = index as i32;
        let handle_key =
            mochios_posix_protocol::fd_handle_key(fd).ok_or(LaunchFdError::InvalidDescriptor)?;
        let metadata_key =
            mochios_posix_protocol::fd_metadata_key(fd).ok_or(LaunchFdError::InvalidDescriptor)?;
        let Some(entry) = table
            .get(fd)
            .filter(|entry| entry.descriptor_flags & FD_CLOEXEC == 0)
        else {
            context
                .remove_value(metadata_key)
                .map_err(LaunchFdError::Context)?;
            context
                .remove_handle(handle_key)
                .map_err(LaunchFdError::Context)?;
            continue;
        };
        let description = describe(entry.handle).ok_or(LaunchFdError::InvalidMetadata)?;
        let requires_handle =
            mochios_posix_protocol::inherited_fd_kind_requires_handle(description.kind)
                .ok_or(LaunchFdError::InvalidMetadata)?;
        if requires_handle != description.has_handle {
            return Err(LaunchFdError::InvalidMetadata);
        }
        let descriptor_flags =
            u8::try_from(entry.descriptor_flags).map_err(|_| LaunchFdError::InvalidMetadata)?;
        let metadata = mochios_posix_protocol::encode_inherited_fd_metadata(
            mochios_posix_protocol::InheritedFdMetadata {
                kind: description.kind,
                open_flags: description.open_flags,
                descriptor_flags,
            },
        )
        .ok_or(LaunchFdError::InvalidMetadata)?;
        if description.has_handle {
            context
                .set_handle(handle_key, entry.handle)
                .map_err(LaunchFdError::Context)?;
        } else {
            context
                .remove_handle(handle_key)
                .map_err(LaunchFdError::Context)?;
        }
        context
            .set_value(metadata_key, metadata)
            .map_err(LaunchFdError::Context)?;
    }
    Ok(())
}

pub fn restore_launch_context<H, C, R, O>(
    table: &mut FdTable<H>,
    descriptor_limit: usize,
    context: &mut C,
    operations: &mut O,
    mut restore: R,
) -> Result<bool, LaunchFdError<C::Error>>
where
    H: Copy,
    C: LaunchContextOps<H>,
    O: HandleOps<H>,
    R: FnMut(mochios_posix_protocol::InheritedFdMetadata, Option<(H, u64)>) -> Option<H>,
{
    if descriptor_limit > DEFAULT_FD_LIMIT || descriptor_limit > i32::MAX as usize {
        return Err(LaunchFdError::InvalidDescriptor);
    }
    *table = FdTable::new();
    let mut restored = false;
    for index in 0..descriptor_limit {
        let fd = index as i32;
        let metadata_key =
            mochios_posix_protocol::fd_metadata_key(fd).ok_or(LaunchFdError::InvalidDescriptor)?;
        let Some(encoded) = context
            .get_value(metadata_key)
            .map_err(LaunchFdError::Context)?
        else {
            continue;
        };
        let metadata = mochios_posix_protocol::decode_inherited_fd_metadata(encoded)
            .ok_or(LaunchFdError::InvalidMetadata)?;
        if metadata.descriptor_flags & mochios_posix_protocol::INHERITED_FD_DESCRIPTOR_CLOEXEC != 0
        {
            return Err(LaunchFdError::InvalidMetadata);
        }
        let handle_key =
            mochios_posix_protocol::fd_handle_key(fd).ok_or(LaunchFdError::InvalidDescriptor)?;
        let handle = context
            .get_handle(handle_key)
            .map_err(LaunchFdError::Context)?;
        let requires_handle =
            mochios_posix_protocol::inherited_fd_kind_requires_handle(metadata.kind)
                .ok_or(LaunchFdError::InvalidMetadata)?;
        let attachment = match (requires_handle, handle) {
            (true, Some(handle)) => {
                let rights = context
                    .get_handle_rights(handle)
                    .map_err(LaunchFdError::Context)?;
                Some((handle, rights))
            }
            (true, None) => return Err(LaunchFdError::MissingHandle),
            (false, Some(_)) => return Err(LaunchFdError::UnexpectedHandle),
            (false, None) => None,
        };
        let rights = attachment.map_or(0, |(_, rights)| rights);
        let handle = restore(metadata, attachment).ok_or(LaunchFdError::InvalidMetadata)?;
        table
            .install_at(
                fd,
                Entry {
                    handle,
                    rights,
                    descriptor_flags: u32::from(metadata.descriptor_flags),
                },
                operations,
            )
            .map_err(|_| LaunchFdError::InvalidDescriptor)?;
        restored = true;
    }
    Ok(restored)
}

impl<H: Copy> Default for FdTable<H> {
    fn default() -> Self {
        Self::new()
    }
}
