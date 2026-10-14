//! Explicit native Handle inheritance for a cloned POSIX address space.

use mnu_abi::{HANDLE_RIGHT_ALL, HANDLE_RIGHT_TRANSFER, HandleInfo, process_create};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidCapture,
    InvalidRecord,
    DuplicateHandle,
    InvalidExclusion,
    NonTransferable(u32),
    TooManyHandles,
    BufferTooSmall,
}

/// Decodes the immutable metadata read from a native Handle capture. Rejects
/// truncation, unknown layouts and oversized tables without changing output.
pub fn decode_capture(bytes: &[u8], output: &mut [HandleInfo]) -> Result<usize, Error> {
    use mnu_abi::handle_snapshot::{HEADER_LEN, RECORD_LEN, VERSION};
    let word = |offset| {
        bytes
            .get(offset..offset + 4)
            .and_then(|value| value.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(Error::InvalidCapture)
    };
    if word(0)? != VERSION || word(8)? as usize != RECORD_LEN || word(12)? != 0 {
        return Err(Error::InvalidCapture);
    }
    let count = word(4)? as usize;
    if count > process_create::MAX_HANDLES {
        return Err(Error::TooManyHandles);
    }
    if bytes.len() != HEADER_LEN + count * RECORD_LEN {
        return Err(Error::InvalidCapture);
    }
    if count > output.len() {
        return Err(Error::BufferTooSmall);
    }
    let record = |index| -> Result<HandleInfo, Error> {
        let offset = HEADER_LEN + index * RECORD_LEN;
        let handle = word(offset)?;
        let reserved = word(offset + 4)?;
        let rights = u64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());
        if handle == 0 || reserved != 0 || rights & !HANDLE_RIGHT_ALL != 0 {
            return Err(Error::InvalidRecord);
        }
        Ok(HandleInfo {
            handle,
            reserved,
            rights,
        })
    };
    for index in 0..count {
        let entry = record(index)?;
        for earlier in 0..index {
            if record(earlier)?.handle == entry.handle {
                return Err(Error::DuplicateHandle);
            }
        }
    }
    for (index, target) in output[..count].iter_mut().enumerate() {
        *target = record(index)?;
    }
    Ok(count)
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
/// Metadata alone is not a reservation: use ProcessCreate with the capture
/// that supplied these records to pin object identity. The kernel enforces
/// TRANSFER and requested-rights containment on those captured references.
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
