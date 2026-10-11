use alloc::vec::Vec;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadError<E> {
    Read(E),
    Allocation,
    InvalidLength,
}

/// Read until explicit EOF, without seeking or treating a short read as EOF.
pub(crate) fn read_to_end<E>(
    chunk_len: usize,
    mut read: impl FnMut(&mut [u8]) -> Result<usize, E>,
) -> Result<Vec<u8>, ReadError<E>> {
    if chunk_len == 0 {
        return Err(ReadError::InvalidLength);
    }
    let mut bytes = Vec::new();
    loop {
        let start = bytes.len();
        let end = start.checked_add(chunk_len).ok_or(ReadError::Allocation)?;
        bytes
            .try_reserve(chunk_len)
            .map_err(|_| ReadError::Allocation)?;
        bytes.resize(end, 0);
        let count = read(&mut bytes[start..]).map_err(ReadError::Read)?;
        if count > chunk_len {
            return Err(ReadError::InvalidLength);
        }
        bytes.truncate(start + count);
        if count == 0 {
            return Ok(bytes);
        }
    }
}
