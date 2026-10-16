//! The kernel writes directly into an already-published owner. No received
//! Handle exists only in an untracked transport-local or return value.
use super::*;

struct Reply {
    native: syscall::IpcObjectHandles,
    borrowed: u32,
}

impl Reply {
    fn new(descriptor: ObjectHandleAttachment<u32>) -> Self {
        let mut native = syscall::IpcObjectHandles::default();
        native.count = 1;
        native.handles[0].handle = descriptor.handle;
        native.handles[0].rights = descriptor.rights;
        Self {
            native,
            borrowed: descriptor.handle,
        }
    }

    fn handles(&self) -> Result<mochios_posix_client::ObjectHandles<u32>, c_int> {
        if self.native.count as usize > self.native.handles.len() || self.native.delivery_flags != 0
        {
            return Err(EIO);
        }
        let mut handles = mochios_posix_client::ObjectHandles::new();
        for entry in self.native.handles.iter().take(self.native.count as usize) {
            if entry.handle == 0 || entry.reserved != 0 {
                return Err(EIO);
            }
            handles
                .push(ObjectHandleAttachment {
                    handle: entry.handle,
                    rights: entry.rights,
                })
                .map_err(|_| EIO)?;
        }
        Ok(handles)
    }
}

impl Drop for Reply {
    fn drop(&mut self) {
        // On an early native error the envelope may still contain outgoing
        // labels. The caller's tracked FD lease keeps that borrow alive and
        // prevents its label from being reused by the receive operation.
        for (index, entry) in self
            .native
            .handles
            .iter()
            .take((self.native.count as usize).min(self.native.handles.len()))
            .enumerate()
        {
            if entry.handle != 0
                && entry.handle != self.borrowed
                && !self.native.handles[..index]
                    .iter()
                    .any(|old| old.handle == entry.handle)
            {
                close_object_handle(entry.handle);
            }
        }
    }
}

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
        || Ok(Reply::new(prepared.descriptor())),
        |reply| {
            let mut response = [0; posix_protocol::HEADER_LEN + 1];
            let request = prepared.request();
            let length = syscall_errno(syscall::raw_syscall6(
                syscall::SyscallNumber::IpcCallObjectHandles,
                u64::from(client.transport().endpoint()),
                request.as_ptr() as u64,
                request.len() as u64,
                response.as_mut_ptr() as u64,
                response.len() as u64,
                (&mut reply.native as *mut syscall::IpcObjectHandles) as u64,
            ))?;
            let response = response.get(..(length & 0xffff_ffff) as usize).ok_or(EIO)?;
            let handles = reply.handles()?;
            let backing = prepared
                .validate::<syscall::SysError>(response, &handles)
                .map_err(map_posix_client_error)?;
            // Validation lends the label, never removes it from the owner.
            consume(u64::from(backing.handle))
        },
    )
}
