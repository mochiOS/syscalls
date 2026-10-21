//! Copy supplementary group arrays without borrowing application memory.
use super::*;

const GID_BYTES: usize = core::mem::size_of::<groups::Gid>();
const MAX_GROUPS: usize = posix_protocol::MAX_SUPPLEMENTARY_GROUPS;

pub(super) fn read(source: *const groups::Gid, output: &mut [u32]) -> Result<(), c_int> {
    if output.len() > MAX_GROUPS {
        return Err(EINVAL);
    }
    let mut bytes = [0; MAX_GROUPS * GID_BYTES];
    // Capture the whole request before decoding or issuing mutating IPC.
    user_copy::read(source.cast(), &mut bytes[..output.len() * GID_BYTES])?;
    let mut native = [0; MAX_GROUPS];
    for (value, bytes) in native.iter_mut().zip(bytes.chunks_exact(GID_BYTES)) {
        *value = groups::Gid::from_ne_bytes(bytes.try_into().expect("gid_t width"));
    }
    groups::widen(&native[..output.len()], output);
    Ok(())
}

pub(super) fn write(destination: *mut groups::Gid, source: &[u32]) -> Result<(), c_int> {
    if source.len() > MAX_GROUPS {
        return Err(EINVAL);
    }
    let mut native = [0; MAX_GROUPS];
    // Check every narrowing conversion before copying any bytes to the caller.
    groups::store(source, &mut native[..source.len()]).map_err(|_| EOVERFLOW)?;
    let mut bytes = [0; MAX_GROUPS * GID_BYTES];
    for (bytes, value) in bytes.chunks_exact_mut(GID_BYTES).zip(native) {
        bytes.copy_from_slice(&value.to_ne_bytes());
    }
    user_copy::write(destination.cast(), &bytes[..source.len() * GID_BYTES])
}
