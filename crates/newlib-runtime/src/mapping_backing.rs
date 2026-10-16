//! The kernel writes directly into an already-published owner. No received
//! Handle exists only in an untracked transport-local or return value.
use super::*;

pub(super) fn with<T: Copy>(
    entry: FdEntry,
    writable: bool,
    consume: impl FnOnce(u64) -> Result<T, c_int>,
) -> Result<T, c_int> {
    let descriptor = ObjectHandleAttachment {
        handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
        rights: entry.rights,
    };
    let client = posix_client().map_err(map_posix_client_error)?;
    let prepared = client
        .prepare_shared_memory_backing(descriptor, writable)
        .map_err(map_posix_client_error)?;
    io_resources::with(
        || Ok(object_reply::Reply::new(Some(prepared.descriptor()))),
        |reply| {
            let mut response = [0; posix_protocol::HEADER_LEN + 1];
            let length = reply.call(
                client.transport().endpoint(),
                prepared.request(),
                &mut response,
            )?;
            let response = &response[..length];
            let handles = reply.handles()?;
            let backing = prepared
                .validate::<syscall::SysError>(response, &handles)
                .map_err(map_posix_client_error)?;
            // Validation lends the label, never removes it from the owner.
            consume(u64::from(backing.handle))
        },
    )
}
