//! Native IPC writes received ownership into an already-published resource.
use super::*;

pub(super) struct Reply {
    native: syscall::IpcObjectHandles,
    borrowed: u32,
}

impl Reply {
    pub(super) fn new(descriptor: Option<ObjectHandleAttachment<u32>>) -> Self {
        let mut native = syscall::IpcObjectHandles::default();
        if let Some(descriptor) = descriptor {
            native.count = 1;
            native.handles[0].handle = descriptor.handle;
            native.handles[0].rights = descriptor.rights;
        }
        Self {
            native,
            borrowed: descriptor.map_or(0, |value| value.handle),
        }
    }

    /// Call only while this owner is published in a callback resource scope.
    pub(super) fn call(
        &mut self,
        endpoint: u32,
        request: &[u8],
        response: &mut [u8],
    ) -> Result<usize, c_int> {
        let length = syscall_errno(syscall::raw_syscall6(
            syscall::SyscallNumber::IpcCallObjectHandles,
            u64::from(endpoint),
            request.as_ptr() as u64,
            request.len() as u64,
            response.as_mut_ptr() as u64,
            response.len() as u64,
            (&mut self.native as *mut syscall::IpcObjectHandles) as u64,
        ))?;
        let length = (length & 0xffff_ffff) as usize;
        if length > response.len() {
            return Err(EIO);
        }
        Ok(length)
    }

    pub(super) fn handles(&self) -> Result<mochios_posix_client::ObjectHandles<u32>, c_int> {
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

    /// After validation and successful FD installation, with native delivery
    /// deferred, the local FD table owns the sole validated reply reference.
    pub(super) fn disarm(&mut self) {
        self.native.count = 0;
    }
}

impl Drop for Reply {
    fn drop(&mut self) {
        // Early native failures can leave outgoing labels in the envelope.
        // The caller's source lease prevents that borrowed label being reused.
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
