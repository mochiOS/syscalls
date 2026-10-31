//! Shared verified-launch transport. Borrowed source references must remain
//! live during the call; only explicitly attached objects can be inherited.
use crate::{capability::application_launch as wire, handle, ipc, syscall};

#[derive(Clone, Copy, Debug)]
pub struct Descriptor {
    pub handle: u32,
    pub rights: u64,
    pub metadata: u64,
}

struct Reply {
    native: ipc::IpcObjectHandles,
    borrowed: [u32; 4],
}
impl Drop for Reply {
    fn drop(&mut self) {
        let entries =
            &self.native.handles[..(self.native.count as usize).min(self.native.handles.len())];
        for (index, entry) in entries.iter().enumerate() {
            // Early failures may leave the outbound envelope unchanged. Those
            // labels are borrowed, and may never be closed as reply ownership.
            if entry.handle != 0
                && !self.borrowed.contains(&entry.handle)
                && !entries[..index]
                    .iter()
                    .any(|old| old.handle == entry.handle)
            {
                let _ = handle::close(entry.handle);
            }
        }
    }
}

fn failure(error: syscall::NativeError) -> syscall::SysError {
    syscall::SysError::from_raw(error.into_raw() as i64)
}

/// Use the registered service's thread endpoint, not a request-supplied PID.
/// The caller's read-scope attachment is interpreted by the broker; the
/// transport never resolves paths or builds application identity/grants.
/// Failure is native or a negative POSIX service status, not C errno.
pub fn spawn_with_stdio(
    destination: u32,
    path: &str,
    arguments: &[&str],
    environment: &[&str],
    read_scope: ipc::IpcObjectHandle,
    stdio: &[Descriptor; 3],
) -> syscall::SysResult<u64> {
    if destination == 0
        || read_scope.handle == 0
        || read_scope.reserved != 0
        || stdio.iter().any(|entry| entry.handle == 0)
    {
        return Err(failure(syscall::NativeError::InvalidArgument));
    }
    let mut request = [0; wire::MAX_BYTES];
    let length = wire::encode(
        &wire::Request {
            path,
            arguments,
            environment,
            stdio_metadata: stdio.map(|entry| entry.metadata),
        },
        &mut request,
    )
    .map_err(|_| failure(syscall::NativeError::InvalidArgument))?;
    let mut owned = Reply {
        native: ipc::IpcObjectHandles::default(),
        borrowed: [
            read_scope.handle,
            stdio[0].handle,
            stdio[1].handle,
            stdio[2].handle,
        ],
    };
    owned.native.count = 4;
    owned.native.handles[0] = read_scope;
    for (destination, source) in owned.native.handles[1..].iter_mut().zip(stdio) {
        *destination = ipc::IpcObjectHandle {
            handle: source.handle,
            reserved: 0,
            rights: source.rights,
        };
    }
    let mut reply = [0; 16];
    let message = ipc::call_object_handles(
        destination,
        &request[..length],
        &mut reply,
        &mut owned.native,
    )?;
    if message as u32 as usize != reply.len()
        || owned.native.delivery_flags != 0
        || owned.native.count != 0
    {
        return Err(failure(syscall::NativeError::InvalidFormat));
    }
    // Native synchronous IPC authenticates this canonical, generation-bound
    // sender. Inspecting another process is neither needed nor authorized by
    // an ordinary application launch. This API takes a thread endpoint.
    if message >> 32 != u64::from(destination) {
        return Err(failure(syscall::NativeError::AccessDenied));
    }
    let status = u64::from_le_bytes(reply[..8].try_into().unwrap());
    let process = u64::from_le_bytes(reply[8..].try_into().unwrap());
    if status != 0 {
        if process != 0 || status > 4095 {
            return Err(failure(syscall::NativeError::InvalidFormat));
        }
        return Err(syscall::SysError::from_raw(-(status as i64)));
    }
    if process == 0 {
        return Err(failure(syscall::NativeError::InvalidFormat));
    }
    Ok(process)
}
