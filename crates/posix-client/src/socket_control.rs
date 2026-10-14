//! Process-local x86_64 C ancillary data, never an IPC wire format. Descriptor
//! numbers are meaningful only in the calling process; adapters must resolve
//! them into explicitly attached native Handles before contacting a worker.
//! No allocation, pointer dereference, FD lookup or Handle acquisition here.

pub const ALIGNMENT: usize = 8;
pub const HEADER_LEN: usize = 16;
pub const SOL_SOCKET: i32 = 1;
pub const SCM_RIGHTS: i32 = 1;
/// Linux-compatible per-message policy, independent of IPC attachment batches.
pub const MAX_RIGHTS: usize = 253;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Malformed,
    UnsupportedControl,
    InvalidDescriptor,
    TooManyDescriptors,
    BufferTooSmall,
}

pub const fn align(length: usize) -> Option<usize> {
    match length.checked_add(ALIGNMENT - 1) {
        Some(length) => Some(length & !(ALIGNMENT - 1)),
        None => None,
    }
}

pub const fn cmsg_len(data_length: usize) -> Option<usize> {
    HEADER_LEN.checked_add(data_length)
}

pub const fn cmsg_space(data_length: usize) -> Option<usize> {
    match align(data_length) {
        Some(length) => HEADER_LEN.checked_add(length),
        None => None,
    }
}

/// Validate the complete chain before exposing even its first descriptor.
/// Unknown control types are rejected rather than silently dropping authority.
/// Absent final alignment padding and a short trailing fragment are allowed,
/// as with CMSG_NXTHDR; a complete but invalid next header is an error.
fn walk(input: &[u8], mut descriptor: impl FnMut(i32)) -> Result<usize, Error> {
    let mut offset = 0;
    let mut count = 0usize;
    while input.len() - offset >= HEADER_LEN {
        let header = &input[offset..offset + HEADER_LEN];
        let length = usize::try_from(u64::from_ne_bytes(header[..8].try_into().unwrap()))
            .map_err(|_| Error::Malformed)?;
        if length < HEADER_LEN || length > input.len() - offset {
            return Err(Error::Malformed);
        }
        let level = i32::from_ne_bytes(header[8..12].try_into().unwrap());
        let kind = i32::from_ne_bytes(header[12..16].try_into().unwrap());
        if (level, kind) != (SOL_SOCKET, SCM_RIGHTS) {
            return Err(Error::UnsupportedControl);
        }
        let data = &input[offset + HEADER_LEN..offset + length];
        if data.len() % 4 != 0 {
            return Err(Error::Malformed);
        }
        count = count
            .checked_add(data.len() / 4)
            .ok_or(Error::TooManyDescriptors)?;
        if count > MAX_RIGHTS {
            return Err(Error::TooManyDescriptors);
        }
        for bytes in data.chunks_exact(4) {
            let fd = i32::from_ne_bytes(bytes.try_into().unwrap());
            if fd < 0 {
                return Err(Error::InvalidDescriptor);
            }
            descriptor(fd);
        }
        let next = align(length).ok_or(Error::Malformed)?;
        if next > input.len() - offset {
            break;
        }
        offset += next;
    }
    Ok(count)
}

/// Output remains untouched on every error, including a malformed late header
/// or an undersized destination. Duplicated FD numbers are intentionally kept:
/// each denotes a distinct received reference to the same OFD.
pub fn decode_rights(input: &[u8], output: &mut [i32]) -> Result<usize, Error> {
    let count = walk(input, |_| ())?;
    if output.len() < count {
        return Err(Error::BufferTooSmall);
    }
    let mut index = 0;
    walk(input, |fd| {
        output[index] = fd;
        index += 1;
    })?;
    Ok(count)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Encoded {
    /// Actual msg_controllen, including only padding that fits the buffer.
    pub length: usize,
    pub descriptors: usize,
    /// Adapter must report MSG_CTRUNC and close references not installed.
    pub truncated: bool,
}

/// Encode receiver-local, already-installed FD numbers. This does not install
/// or close any reference. The adapter must reserve descriptor slots first and
/// ensure truncated, discarded and failed transfers cannot leak Handles.
/// No partial FD is emitted; bytes outside the returned extent are untouched.
pub fn encode_rights(descriptors: &[i32], output: &mut [u8]) -> Result<Encoded, Error> {
    if descriptors.len() > MAX_RIGHTS {
        return Err(Error::TooManyDescriptors);
    }
    if descriptors.iter().any(|fd| *fd < 0) {
        return Err(Error::InvalidDescriptor);
    }
    let count = output.len().saturating_sub(HEADER_LEN) / 4;
    let count = count.min(descriptors.len());
    if count == 0 {
        return Ok(Encoded {
            length: 0,
            descriptors: 0,
            truncated: !descriptors.is_empty(),
        });
    }
    // MAX_RIGHTS bounds both arithmetic operations.
    let length = cmsg_len(count * 4).unwrap();
    let space = cmsg_space(count * 4).unwrap().min(output.len());
    output[..space].fill(0);
    output[..8].copy_from_slice(&(length as u64).to_ne_bytes());
    output[8..12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
    output[12..16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
    for (fd, bytes) in descriptors[..count]
        .iter()
        .zip(output[HEADER_LEN..length].chunks_exact_mut(4))
    {
        bytes.copy_from_slice(&fd.to_ne_bytes());
    }
    Ok(Encoded {
        length: space,
        descriptors: count,
        truncated: count != descriptors.len(),
    })
}
