/// Maximum number of vectors advertised by the mochiOS newlib headers.
pub const IOV_MAX: usize = 1024;

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
