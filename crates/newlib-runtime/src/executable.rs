//! Code references are opaque native authority, never filesystem paths or FDs.
use super::*;
use mochios_capability_protocol::{executables as wire, resources};
use mochios_posix_client::{ObjectHandles, ObjectTransport, image_preparation::Backend};
#[derive(Default)]
pub(super) struct Reference(pub u32);
impl Drop for Reference {
    fn drop(&mut self) {
        if self.0 != 0 {
            let _delivery = defer_native_delivery();
            close_object_handle(self.0);
        }
    }
}
fn inherited(key: u64) -> Result<u32, c_int> {
    let raw = syscall_errno(syscall::raw_syscall1(
        syscall::SyscallNumber::LaunchHandleGet,
        key,
    ))?;
    u32::try_from(raw).ok().filter(|v| *v != 0).ok_or(EACCES)
}
pub(super) fn retained_context_key(key: u64) -> bool {
    matches!(key, resources::ROOT_KEY | resources::CONTROL_KEY)
}
/// Reconstruct the existing signed-startup labels after a fork. This merely
/// labels captured references: the capture still enforces their exact rights.
pub(super) fn inherit_context(
    grants: &mut [mnu_abi::process_create::HandleGrant],
) -> Result<(), c_int> {
    for key in [resources::ROOT_KEY, resources::CONTROL_KEY] {
        let handle = match inherited(key) {
            Ok(handle) => handle,
            Err(ENOENT) => continue, // Older/non-application launchers have no Bundle.
            Err(error) => return Err(error),
        };
        let grant = grants
            .iter_mut()
            .find(|grant| grant.source == handle)
            .ok_or(EBADF)?;
        grant.key = key;
    }
    Ok(())
}
fn request(
    handle: u32,
    selection: wire::Request<'_>,
    pending: &mut Reference,
) -> Result<(), c_int> {
    let mut bytes = [0; wire::MAX_BYTES];
    let length = selection.encode(&mut bytes).map_err(|_| EINVAL)?;
    let endpoint = inherited(resources::CONTROL_KEY)?;
    let transport = SyscallEndpointTransport::new(endpoint);
    let mut handles = ObjectHandles::new();
    handles
        .push(ObjectHandleAttachment {
            handle,
            rights: syscall::HANDLE_RIGHT_TRANSFER,
        })
        .map_err(|_| EIO)?;
    let mut response = [0; 8];
    let _delivery = defer_native_delivery();
    let result = transport.call_with_handles(&bytes[..length], &mut response, &mut handles);
    let status = i64::from_le_bytes(response);
    let expected = syscall::HANDLE_RIGHT_TRANSFER
        | if selection.operation == wire::SELECT {
            syscall::HANDLE_RIGHT_DUPLICATE
        } else {
            syscall::HANDLE_RIGHT_READ
        };
    if matches!(result, Ok(8))
        && status == 0
        && handles.len() == 1
        && handles.get(0).is_some_and(|object| {
            object.handle != 0
                && object.handle != handle
                && object.handle != endpoint
                && object.rights == expected
        })
    {
        pending.0 = handles.get(0).unwrap().handle;
        handles.clear();
        return Ok(());
    }
    for object in handles.iter() {
        if object.handle != handle && object.handle != endpoint {
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
pub extern "C" fn mochi_executable_open(alias: *const c_char, name: *const c_char) -> u32 {
    result_with_errno(
        io_resources::with(
            || Ok(Reference::default()),
            |pending| {
                let mut a = [0; 129];
                let na = user_copy::capture_text(alias, &mut a, ENAMETOOLONG)?;
                let mut n = [0; 129];
                let nn = user_copy::capture_text(name, &mut n, ENAMETOOLONG)?;
                let selection = wire::Request {
                    operation: wire::SELECT,
                    alias: core::str::from_utf8(&a[..na]).map_err(|_| EINVAL)?,
                    name: core::str::from_utf8(&n[..nn]).map_err(|_| EINVAL)?,
                };
                request(inherited(resources::ROOT_KEY)?, selection, pending)?;
                let _delivery = defer_native_delivery();
                Ok(core::mem::replace(&mut pending.0, 0))
            },
        ),
        0,
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn mochi_executable_close(handle: u32) -> c_int {
    result_with_errno(
        syscall_errno(syscall::raw_syscall1(
            syscall::SyscallNumber::HandleClose,
            handle as u64,
        ))
        .map(|_| 0),
        -1,
    )
}
#[unsafe(no_mangle)]
pub extern "C" fn mochi_executable_execve(
    handle: u32,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    result_with_errno(replace(handle, argv, envp).map(|()| 0), -1)
}
pub(super) fn replace(
    handle: u32,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> Result<(), c_int> {
    io_resources::with(
        || {
            let _delivery = defer_native_delivery();
            let copied = syscall_errno(syscall::raw_syscall2(
                syscall::SyscallNumber::HandleDuplicate,
                handle as u64,
                syscall::HANDLE_RIGHT_DUPLICATE | syscall::HANDLE_RIGHT_TRANSFER,
            ))?;
            Ok(Reference(u32::try_from(copied).map_err(|_| EIO)?))
        },
        |token| {
            let mut inputs = exec_inputs::Inputs::new();
            inputs.capture_fd(argv, envp)?;
            with_exec_fd_snapshot(|fds| {
                io_resources::with(
                    || Ok(Reference::default()),
                    |root| {
                        request(
                            token.0,
                            wire::Request {
                                operation: wire::ROOT,
                                alias: "",
                                name: "",
                            },
                            root,
                        )?;
                        exec_handle::replace_with_reader(
                            Reader(token.0),
                            true,
                            root.0,
                            "package-executable",
                            b"package-executable",
                            &inputs,
                            fds,
                            address_space::snapshot()?.byte_ceiling(),
                        )
                    },
                )
            })
        },
    )
}
#[repr(C)]
pub struct SpawnedProcess {
    pid: c_int,
    process: u32,
}
#[unsafe(no_mangle)]
pub extern "C" fn mochi_executable_spawn(
    output: *mut SpawnedProcess,
    reference: u32,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if output.is_null() {
        return EINVAL;
    }
    let attributes = match spawn_attributes::read_optional(attrp) {
        Ok(value) => value,
        Err(error) => return error,
    };
    // Pin the reference before cloning the caller. Child cleanup and exec
    // failure reporting use the same owners as normal posix_spawn.
    match io_resources::with(
        || {
            let _delivery = defer_native_delivery();
            let copied = syscall_errno(syscall::raw_syscall2(
                syscall::SyscallNumber::HandleDuplicate,
                reference as u64,
                syscall::HANDLE_RIGHT_DUPLICATE | syscall::HANDLE_RIGHT_TRANSFER,
            ))?;
            Ok(Reference(u32::try_from(copied).map_err(|_| EIO)?))
        },
        |token| {
            Ok(spawn_file_actions::with(file_actions, |actions| {
                spawn_resources::with(|resources| {
                    spawn_with_resources_target(
                        SpawnOutput::Reference(output.cast()),
                        SpawnTarget::Executable(token.0),
                        actions,
                        attributes,
                        argv,
                        envp,
                        resources,
                    )
                })
            }))
        },
    ) {
        Ok(result) => result,
        Err(error) => error,
    }
}
pub(super) struct Reader(pub u32);
// The original Runtime owns allocation, reference release and callback rules.
// Only code acquisition changes; no pathname fallback exists in this reader.
unsafe impl Backend for Reader {
    fn critical<T>(operation: impl FnOnce() -> T) -> T {
        exec_image::Runtime::critical(operation)
    }
    fn allocate(length: usize) -> *mut u8 {
        exec_image::Runtime::allocate(length)
    }
    unsafe fn deallocate(pointer: *mut u8) {
        unsafe { exec_image::Runtime::deallocate(pointer) }
    }
    fn close(handle: u32) {
        exec_image::Runtime::close(handle)
    }
    fn read_at(&self, image: u32, out: &mut [u8], offset: usize) -> Result<usize, c_int> {
        exec_image::Runtime.read_at(image, out, offset)
    }
    fn open_library(&self, path: &[u8]) -> Result<ObjectHandleAttachment<u32>, c_int> {
        io_resources::with(
            || Ok(Reference::default()),
            |pending| {
                request(
                    self.0,
                    wire::Request {
                        operation: wire::LIBRARY,
                        alias: "",
                        name: core::str::from_utf8(path).map_err(|_| EINVAL)?,
                    },
                    pending,
                )?;
                let _delivery = defer_native_delivery();
                Ok(ObjectHandleAttachment {
                    handle: core::mem::replace(&mut pending.0, 0),
                    rights: syscall::HANDLE_RIGHT_READ | syscall::HANDLE_RIGHT_TRANSFER,
                })
            },
        )
    }
    fn validate_library(&self, _: ObjectHandleAttachment<u32>) -> Result<(), c_int> {
        Ok(())
    }
    fn validate_captured(
        &self,
        source: mochios_posix_client::image_preparation::Source<'_>,
        bytes: &[u8],
    ) -> Result<(), c_int> {
        exec_image::Runtime.validate_captured(source, bytes)
    }
    fn entropy(&self, out: &mut [u8]) -> Result<(), c_int> {
        exec_image::Runtime.entropy(out)
    }
    fn create_image(&self, length: usize) -> Result<u32, c_int> {
        exec_image::Runtime.create_image(length)
    }
    fn write_at(&self, image: u32, bytes: &[u8], offset: usize) -> Result<usize, c_int> {
        exec_image::Runtime.write_at(image, bytes, offset)
    }
    fn readonly_image(&self, image: u32) -> Result<u32, c_int> {
        exec_image::Runtime.readonly_image(image)
    }
    fn readonly_metadata(&self, image: u32) -> Result<u32, c_int> {
        exec_image::Runtime.readonly_metadata(image)
    }
}
