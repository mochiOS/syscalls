//! Process-local named semaphore mappings, keyed by native object identity.
//! A name can be unlinked/recreated while its old mapped object is still live.

pub trait MappingOps<H> {
    type Error;
    fn same_object(&mut self, left: H, right: H) -> Result<bool, Self::Error>;
    fn map(&mut self, handle: H) -> Result<u64, Self::Error>;
    fn unmap(&mut self, address: u64) -> Result<(), Self::Error>;
    fn close_handle(&mut self, handle: H);
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Invalid,
    Full,
    Overflow,
    Backend(E),
}

#[derive(Clone, Copy)]
struct Entry<H> {
    handle: H,
    address: u64,
    references: u32,
}

/// Synchronize externally, including across address-space/Handle-table clone.
/// Copying this table alone does not duplicate ownership of native resources.
pub struct Mappings<H, const N: usize> {
    entries: [Option<Entry<H>>; N],
}

impl<H: Copy, const N: usize> Mappings<H, N> {
    pub const fn new() -> Self {
        Self { entries: [None; N] }
    }

    /// Takes ownership of every incoming Handle, even on failure. Repeated
    /// opens share one pointer and retain a separate POSIX close reference.
    pub fn adopt<O: MappingOps<H>>(
        &mut self,
        handle: H,
        operations: &mut O,
    ) -> Result<u64, Error<O::Error>> {
        let result = (|| {
            for entry in self.entries.iter_mut().flatten() {
                if operations
                    .same_object(entry.handle, handle)
                    .map_err(Error::Backend)?
                {
                    entry.references = entry.references.checked_add(1).ok_or(Error::Overflow)?;
                    return Ok((entry.address, false));
                }
            }
            let slot = self
                .entries
                .iter_mut()
                .find(|entry| entry.is_none())
                .ok_or(Error::Full)?;
            let address = operations.map(handle).map_err(Error::Backend)?;
            *slot = Some(Entry {
                handle,
                address,
                references: 1,
            });
            Ok((address, true))
        })();
        match result {
            Ok((address, true)) => Ok(address),
            Ok((address, false)) => {
                operations.close_handle(handle);
                Ok(address)
            }
            Err(error) => {
                operations.close_handle(handle);
                Err(error)
            }
        }
    }

    pub fn close<O: MappingOps<H>>(
        &mut self,
        address: u64,
        operations: &mut O,
    ) -> Result<(), Error<O::Error>> {
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_some_and(|entry| entry.address == address))
            .ok_or(Error::Invalid)?;
        let entry = slot.as_mut().unwrap();
        if entry.references > 1 {
            entry.references -= 1;
            return Ok(());
        }
        // Preserve ownership for a retry if the mapping could not be released.
        operations.unmap(entry.address).map_err(Error::Backend)?;
        operations.close_handle(entry.handle);
        *slot = None;
        Ok(())
    }
}
