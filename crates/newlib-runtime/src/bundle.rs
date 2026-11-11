//! C bundle access uses only inherited native authority. Environment variables
//! and absolute paths cannot choose another package or substitute its identity.
use super::*;
use mochios_capability_protocol::resources as wire;
use mochios_posix_client::{ObjectHandles, ObjectTransport};

struct Pending {
    handle: u32,
    completion: Option<mochios_posix_client::upcall_guard::Guard<'static>>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if self.handle != 0 {
            close_object_handle(self.handle);
        }
    }
}
fn inherited(key: u64) -> Result<u32, c_int> {
    let raw = syscall_errno(syscall::raw_syscall1(
        syscall::SyscallNumber::LaunchHandleGet,
        key,
    ))?;
    u32::try_from(raw).ok().filter(|h| *h != 0).ok_or(EACCES)
}
fn request(
    alias: *const c_char,
    name: Option<*const c_char>,
    operation: u16,
    pending: &mut Pending,
) -> Result<(), c_int> {
    let mut a = [0; 128];
    let na = user_copy::capture_text(alias, &mut a, ENAMETOOLONG)?;
    let mut n = [0; posix_protocol::MAX_PATH_LEN];
    let nn = match name {
        Some(name) => user_copy::capture(name, &mut n)?,
        None => 0,
    };
    let selection = wire::Request {
        operation,
        alias: core::str::from_utf8(&a[..na]).map_err(|_| EINVAL)?,
        name: core::str::from_utf8(&n[..nn]).map_err(|_| EINVAL)?,
    };
    let mut bytes = [0; wire::MAX_BYTES];
    let length = selection.encode(&mut bytes).map_err(|_| EINVAL)?;
    let root = inherited(wire::ROOT_KEY)?;
    let endpoint = inherited(wire::CONTROL_KEY)?;
    let transport = SyscallEndpointTransport::new(endpoint);
    let mut handles = ObjectHandles::new();
    handles
        .push(ObjectHandleAttachment {
            handle: root,
            rights: syscall::HANDLE_RIGHT_TRANSFER,
        })
        .map_err(|_| EIO)?;
    let mut response = [0; 8];
    let _delivery = defer_native_delivery();
    let result = transport.call_with_handles(&bytes[..length], &mut response, &mut handles);
    let status = i64::from_le_bytes(response);
    let expected = syscall::HANDLE_RIGHT_READ
        | syscall::HANDLE_RIGHT_SEEK
        | syscall::HANDLE_RIGHT_DUPLICATE
        | syscall::HANDLE_RIGHT_TRANSFER
        | if operation == wire::OPEN {
            syscall::HANDLE_RIGHT_MAP
        } else {
            0
        };
    if matches!(result, Ok(8))
        && status == 0
        && (operation == wire::CHECK && handles.is_empty()
            || operation != wire::CHECK
                && handles.len() == 1
                && handles
                    .get(0)
                    .is_some_and(|h| h.handle != root && h.handle != 0 && h.rights == expected))
    {
        pending.handle = handles.get(0).map_or(0, |h| h.handle);
        handles.clear();
        return Ok(());
    }
    for object in handles.iter() {
        if object.handle != root {
            transport.close_received_handle(object.handle);
        }
    }
    result.map_err(|e| map_kernel_errno(e.raw()))?;
    if status < 0 {
        return Err(mochios_posix_client::newlib_errno::from_status(status));
    }
    Err(EIO)
}
#[unsafe(no_mangle)]
pub extern "C" fn mochi_bundle_check(alias: *const c_char) -> c_int {
    result_with_errno(
        io_resources::with(
            || {
                Ok(Pending {
                    handle: 0,
                    completion: None,
                })
            },
            |pending| request(alias, None, wire::CHECK, pending).map(|_| 0),
        ),
        -1,
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn mochi_bundle_open(alias: *const c_char, name: *const c_char) -> c_int {
    result_with_errno(
        io_resources::with(
            || {
                Ok(Pending {
                    handle: 0,
                    completion: None,
                })
            },
            |pending| {
                request(alias, Some(name), wire::OPEN, pending)?;
                pending.completion = defer_native_delivery();
                file_handle_import::import(pending.handle, O_CLOEXEC)
            },
        ),
        -1,
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn mochi_bundle_directory_open(
    alias: *const c_char,
    path: *mut c_char,
    capacity: usize,
) -> u64 {
    result_with_errno(
        io_resources::with(
            || {
                Ok(Pending {
                    handle: 0,
                    completion: None,
                })
            },
            |pending| {
                if capacity < resource_views::PATH_BYTES {
                    return Err(ENAMETOOLONG);
                }
                request(alias, None, wire::DIRECTORY, pending)?;
                pending.completion = defer_native_delivery();
                resource_views::publish(&mut pending.handle, path)
            },
        ),
        0,
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn mochi_bundle_directory_close(token: u64) -> c_int {
    result_with_errno(resource_views::close(token).map(|_| 0), -1)
}
