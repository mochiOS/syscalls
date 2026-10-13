//! Explicit native Handle inheritance for a cloned POSIX address space.

use mnu_abi::{HANDLE_RIGHT_ALL, HANDLE_RIGHT_TRANSFER, HandleInfo, process_create};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidRecord,
    DuplicateHandle,
    InvalidExclusion,
    NonTransferable(u32),
    TooManyHandles,
    BufferTooSmall,
}

/// Preserves native Handle slots and rights, including references used by
/// CLOEXEC descriptors: CLOEXEC applies to exec, not fork.
///
/// Exclusions must explicitly identify existing, distinct caller-selected
/// transient references (for example the address-space snapshot itself).
/// Non-transferable references are never silently discarded. On any error the
/// output is unchanged. Input order need not be sorted.
///
/// Keys here are opaque user-space slot labels, not original LaunchContext
/// keys or FD numbers. LaunchContext policy must be reconstructed separately.
/// Metadata is not a reservation: ProcessCreate must revalidate each live
/// source and enforce TRANSFER and requested-rights containment.
pub fn prepare(
    records: &[HandleInfo],
    exclusions: &[u32],
    output: &mut [process_create::HandleGrant],
) -> Result<usize, Error> {
    for (index, record) in records.iter().enumerate() {
        if record.handle == 0 || record.reserved != 0 || record.rights & !HANDLE_RIGHT_ALL != 0 {
            return Err(Error::InvalidRecord);
        }
        if records[..index]
            .iter()
            .any(|other| other.handle == record.handle)
        {
            return Err(Error::DuplicateHandle);
        }
    }
    for (index, handle) in exclusions.iter().enumerate() {
        if exclusions[..index].contains(handle)
            || !records.iter().any(|record| record.handle == *handle)
        {
            return Err(Error::InvalidExclusion);
        }
    }
    let count = records.len() - exclusions.len();
    if count > process_create::MAX_HANDLES {
        return Err(Error::TooManyHandles);
    }
    if count > output.len() {
        return Err(Error::BufferTooSmall);
    }
    for record in records {
        if !exclusions.contains(&record.handle) && record.rights & HANDLE_RIGHT_TRANSFER == 0 {
            return Err(Error::NonTransferable(record.handle));
        }
    }
    let mut written = 0;
    for record in records {
        if exclusions.contains(&record.handle) {
            continue;
        }
        output[written] = process_create::HandleGrant {
            key: u64::from(record.handle),
            source: record.handle,
            target: record.handle,
            rights: record.rights,
        };
        written += 1;
    }
    Ok(written)
}

/// Fork slot labels transfer resources into a copied address space; they are
/// not declarations that all those resources should survive a later exec.
/// Removing the opaque labels leaves the child's owned Handles untouched.
pub fn clear_transient_context<E>(
    grants: &[process_create::HandleGrant],
    retained_key: u64,
    mut remove: impl FnMut(u64) -> Result<(), E>,
) -> Result<(), E> {
    for grant in grants {
        if grant.key != retained_key {
            remove(grant.key)?;
        }
    }
    Ok(())
}
