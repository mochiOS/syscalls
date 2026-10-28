//! Execute retained image objects. Neither authorization nor loading reopens a path.
use super::*;
use sha2::{Digest, Sha256};

pub(super) fn with_startup(
    inputs: &exec_inputs::Inputs,
    execfn: &[u8],
    fds: &FdTable<FdObject>,
    process: mochios_posix_client::process_image::Process<'_>,
    operation: impl FnOnce(&[u8]) -> Result<(), c_int>,
) -> Result<(), c_int> {
    let mut arguments = [&[][..]; MAX_EXEC_VECTOR_ENTRIES];
    let mut environment = [&[][..]; MAX_EXEC_VECTOR_ENTRIES];
    let (mut argument_count, mut environment_count) =
        inputs.vectors(&mut arguments, &mut environment);
    if argument_count == 0 {
        arguments[0] = execfn;
        argument_count = 1;
    }
    let mut retained = 0;
    for index in 0..environment_count {
        if process.identity.allows_environment(environment[index]) {
            environment[retained] = environment[index];
            retained += 1;
        }
    }
    environment_count = retained;
    let mut random = [0; 16];
    let count = syscall_errno(syscall::raw_syscall2(
        syscall::SyscallNumber::RandomFill,
        random.as_mut_ptr() as u64,
        random.len() as u64,
    ))?;
    if count != random.len() as u64 {
        return Err(EIO);
    }
    // The policy-page reference must also be reclaimed if a signal handler
    // abandons exec preparation rather than unwinding this Rust frame.
    io_resources::with(
        || image_startup::Plan::new(random),
        |plan| {
            let mut startup = [0; MAX_STARTUP_IMAGE_BYTES];
            let length = mochios_posix_client::process_image::encode_initial_stack_for_process(
                &arguments[..argument_count],
                &environment[..environment_count],
                execfn,
                random,
                &plan.auxiliary(),
                process,
                &mut startup,
            )
            .map_err(|error| match error {
                mochios_posix_client::process_image::EncodeError::ImageTooLarge
                | mochios_posix_client::process_image::EncodeError::EmptyArgumentVector => E2BIG,
                mochios_posix_client::process_image::EncodeError::InvalidText => EINVAL,
                mochios_posix_client::process_image::EncodeError::Codec(_) => EIO,
            })?;
            let length =
                mnu_abi::process_image::attach_mappings(&mut startup, length, &plan.mappings())
                    .map_err(|_| EIO)?;
            let length = attach_fd_launch_context(fds, &mut startup, length)?;
            operation(&startup[..length])
        },
    )
}

pub(super) fn replace(
    fd: c_int,
    argv: *const *const c_char,
    envp: *const *const c_char,
    fds: &FdTable<FdObject>,
) -> Result<(), c_int> {
    // The enclosing exec snapshot pins every original native reference. A
    // concurrent close/reuse cannot substitute another file for this entry.
    let entry = fds.get(fd).ok_or(EBADF)?;
    if entry.handle.kind != FdKind::ObjectFile {
        return Err(EACCES);
    }
    if !mochios_posix_client::fd::access_allows_read(entry.handle.open_flags as u32) {
        return Err(EBADF);
    }
    if entry.rights & posix_protocol::CHECK_EXECUTABLE_RIGHTS
        != posix_protocol::CHECK_EXECUTABLE_RIGHTS
    {
        return Err(EACCES);
    }
    let image = u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?;
    let mut inputs = exec_inputs::Inputs::new();
    inputs.capture_fd(argv, envp)?;
    let client = posix_client().map_err(map_posix_client_error)?;
    client
        .check_executable(ObjectHandleAttachment {
            handle: image,
            rights: entry.rights,
        })
        .map_err(map_posix_client_error)?;
    // An opaque execution key, not a reconstructed pathname or FD number.
    const IDENTITY: &str = "fexecve";
    let ceiling = address_space::snapshot()?.byte_ceiling();
    replace_image(image, IDENTITY, IDENTITY.as_bytes(), &inputs, fds, ceiling)
}

/// Own the newly opened image through callbacks that may abandon the C call.
/// The descriptor variant instead borrows the surrounding exec FD snapshot.
struct OpenImage(u32);
impl Drop for OpenImage {
    fn drop(&mut self) {
        let _delivery = defer_native_delivery();
        close_object_handle(self.0);
    }
}

pub(super) fn replace_path(
    inputs: &exec_inputs::Inputs,
    fds: &FdTable<FdObject>,
) -> Result<(), c_int> {
    let ceiling = address_space::snapshot()?.byte_ceiling();
    let client = posix_client().map_err(map_posix_client_error)?;
    let path = inputs.path();
    io_resources::with(
        || {
            let opened = client
                .open_at(
                    if path.first() == Some(&b'/') {
                        OpenAtBase::ProcessRoot
                    } else {
                        OpenAtBase::ProcessCwd
                    },
                    posix_protocol::OPEN_READ | posix_protocol::OPEN_EXECUTE,
                    0,
                    path,
                )
                .map_err(map_posix_client_error)?;
            let image = OpenImage(opened.handle);
            // Positional reads and explicit broker transfer; no cursor authority.
            let required = posix_protocol::CHECK_EXECUTABLE_RIGHTS;
            if opened.rights & required != required {
                return Err(EACCES);
            }
            Ok(image)
        },
        |image| replace_image(image.0, "execve", path, inputs, fds, ceiling),
    )
}

fn replace_image(
    image: u32,
    identity: &str,
    execfn: &[u8],
    inputs: &exec_inputs::Inputs,
    fds: &FdTable<FdObject>,
    ceiling: u64,
) -> Result<(), c_int> {
    let credentials = mochios_posix_client::process_image::Identity::from(
        posix_client()
            .map_err(map_posix_client_error)?
            .session_info()
            .map_err(map_posix_client_error)?,
    );
    exec_image::with_image(image, inputs, credentials, |image, auxiliary, lifecycle| {
        with_startup(
            inputs,
            execfn,
            fds,
            mochios_posix_client::process_image::Process {
                image: auxiliary,
                identity: credentials,
                lifecycle,
            },
            |startup| {
                let digest = digest(image)?;
                authorize(image, identity, &digest)?;
                match syscall::image::replace_bounded(image, identity, startup, ceiling) {
                    Ok(never) => match never {},
                    Err(error) => Err(mochios_posix_client::image_error::errno(error.raw())),
                }
            },
        )
    })
}

fn digest(image: u32) -> Result<[u8; 32], c_int> {
    let mut hash = Sha256::new();
    let mut bytes = [0; mnu_abi::provider::MAX_DATA_LEN];
    let mut offset = 0u64;
    loop {
        let count = syscall_errno(syscall::raw_syscall4(
            syscall::SyscallNumber::HandleReadAt,
            u64::from(image),
            bytes.as_mut_ptr() as u64,
            bytes.len() as u64,
            offset,
        ))?;
        if count > bytes.len() as u64 {
            return Err(EIO);
        }
        if count == 0 {
            return Ok(hash.finalize().into());
        }
        offset = offset
            .checked_add(count)
            .filter(|offset| *offset <= mnu_abi::exec::MAX_CAPTURED_IMAGE_BYTES as u64)
            .ok_or(EFBIG)?;
        hash.update(&bytes[..count as usize]);
    }
}

fn authorize(image: u32, identity: &str, digest: &[u8; 32]) -> Result<(), c_int> {
    let endpoint = syscall_errno(syscall::raw_syscall2(
        syscall::SyscallNumber::FindProcessByName,
        CAPABILITY_SERVICE_NAME.as_ptr() as u64,
        CAPABILITY_SERVICE_NAME.len() as u64,
    ))?;
    if endpoint == 0 {
        return Err(ENOENT);
    }
    let mut request = [0; 40 + mochios_capability_protocol::MAX_EXECUTABLE_IDENTITY_LEN];
    let length = mochios_capability_protocol::encode_authorize_exec_object_request(
        identity,
        digest,
        &mut request,
    )
    .map_err(|_| EINVAL)?;
    let mut handles = mnu_abi::IpcObjectHandles::default();
    handles.count = 1;
    handles.handles[0] = mnu_abi::IpcObjectHandle {
        handle: image,
        reserved: 0,
        rights: syscall::HANDLE_RIGHT_READ,
    };
    let mut reply = [0; 8];
    // Reply ownership must be drained before asynchronous callbacks reopen.
    // This broker performs no Provider I/O, and the borrowed image stays pinned.
    let _delivery = defer_native_delivery();
    let received = syscall_errno(syscall::raw_syscall6(
        syscall::SyscallNumber::IpcCallObjectHandles,
        endpoint,
        request.as_ptr() as u64,
        length as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
        &mut handles as *mut _ as u64,
    ));
    let unexpected = handles.count != 0;
    let count = (handles.count as usize).min(handles.handles.len());
    for (index, attached) in handles.handles[..count].iter().enumerate() {
        if attached.handle != 0
            && attached.handle != image
            && !handles.handles[..index]
                .iter()
                .any(|old| old.handle == attached.handle)
        {
            close_object_handle(attached.handle);
        }
    }
    let message = received?;
    if message as u32 as usize != reply.len() || handles.delivery_flags != 0 {
        return Err(EIO);
    }
    let status = u64::from_le_bytes(reply);
    if status != 0 {
        return Err(i64::try_from(status).map(map_kernel_errno).unwrap_or(EIO));
    }
    if unexpected {
        return Err(EIO);
    }
    Ok(())
}
