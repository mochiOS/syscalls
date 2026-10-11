/// Maximum number of vectors advertised by the mochiOS newlib headers.
pub const IOV_MAX: usize = 1024;

/// Bound temporary storage to the native Handle I/O transfer limit. Larger
/// requests may return a short transfer, but never issue a second operation.
pub const MAX_TRANSFER_BYTES: usize = 128 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum TransferError<E> {
    InvalidResult,
    Io(E),
}

/// Gather a validated vector prefix and submit it as one I/O operation. The
/// caller owns pointer validation; this helper never dereferences C pointers.
pub fn write<E>(
    count: usize,
    bytes: &mut [u8],
    mut length: impl FnMut(usize) -> usize,
    mut copy: impl FnMut(usize, &mut [u8]),
    io: impl FnOnce(&[u8]) -> Result<usize, E>,
) -> Result<usize, TransferError<E>> {
    let mut offset = 0;
    for index in 0..count {
        let size = length(index).min(bytes.len() - offset);
        if size != 0 {
            copy(index, &mut bytes[offset..offset + size]);
            offset += size;
        }
        if offset == bytes.len() {
            break;
        }
    }
    let transferred = io(bytes).map_err(TransferError::Io)?;
    if transferred > bytes.len() {
        return Err(TransferError::InvalidResult);
    }
    Ok(transferred)
}

/// Submit one read and scatter only the returned prefix. In particular, a
/// short read never starts another blocking operation for the next vector.
pub fn read<E>(
    count: usize,
    bytes: &mut [u8],
    mut length: impl FnMut(usize) -> usize,
    mut copy: impl FnMut(usize, &[u8]),
    io: impl FnOnce(&mut [u8]) -> Result<usize, E>,
) -> Result<usize, TransferError<E>> {
    let transferred = io(bytes).map_err(TransferError::Io)?;
    if transferred > bytes.len() {
        return Err(TransferError::InvalidResult);
    }
    let mut offset = 0;
    for index in 0..count {
        let size = length(index).min(transferred - offset);
        if size != 0 {
            copy(index, &bytes[offset..offset + size]);
            offset += size;
        }
        if offset == transferred {
            break;
        }
    }
    Ok(transferred)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VectorError {
    InvalidCount,
    InvalidLength,
    NullBuffer,
}

/// Validate all vector metadata before any read or write can have side effects.
/// `metadata` returns whether the base is null and the length. A null base is
/// allowed for an empty vector, since no memory is accessed for it.
pub fn validate(
    count: i32,
    mut metadata: impl FnMut(usize) -> (bool, usize),
) -> Result<usize, VectorError> {
    let count = usize::try_from(count).map_err(|_| VectorError::InvalidCount)?;
    if count > IOV_MAX {
        return Err(VectorError::InvalidCount);
    }
    let mut total = 0usize;
    for index in 0..count {
        let (null, length) = metadata(index);
        if null && length != 0 {
            return Err(VectorError::NullBuffer);
        }
        total = total
            .checked_add(length)
            .ok_or(VectorError::InvalidLength)?;
        if total > isize::MAX as usize {
            return Err(VectorError::InvalidLength);
        }
    }
    Ok(total)
}
