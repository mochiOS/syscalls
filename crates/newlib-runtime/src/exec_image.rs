//! Callback-aware libc adapter for the shared loader. Authority to replace an
//! image is still requested only by exec_handle after preparation succeeds.
use super::*;
use mochios_posix_client::image_preparation::{self as shared, Backend, Environment, Preparation};

pub(super) struct Runtime;

// malloc/free supply max_align_t storage. Every resource publication and
// release runs with native callback delivery deferred, as before extraction.
unsafe impl Backend for Runtime {
    fn critical<T>(operation: impl FnOnce() -> T) -> T {
        let _delivery = defer_native_delivery();
        operation()
    }
    fn allocate(length: usize) -> *mut u8 {
        unsafe { malloc(length) }.cast()
    }
    unsafe fn deallocate(pointer: *mut u8) {
        unsafe { free(pointer.cast()) };
    }
    fn close(handle: u32) {
        close_object_handle(handle);
    }
    fn read_at(&self, image: u32, output: &mut [u8], offset: usize) -> Result<usize, c_int> {
        let count = syscall_errno(syscall::raw_syscall4(
            syscall::SyscallNumber::HandleReadAt,
            image as u64,
            output.as_mut_ptr() as u64,
            output.len() as u64,
            offset as u64,
        ))?;
        usize::try_from(count).map_err(|_| EIO)
    }
    fn open_library(&self, path: &[u8]) -> Result<ObjectHandleAttachment<u32>, c_int> {
        posix_client()
            .map_err(map_posix_client_error)?
            .open_at(
                if path.first() == Some(&b'/') {
                    OpenAtBase::ProcessRoot
                } else {
                    OpenAtBase::ProcessCwd
                },
                posix_protocol::OPEN_READ | posix_protocol::OPEN_NONBLOCK,
                0,
                path,
            )
            .map_err(map_posix_client_error)
    }
    fn validate_library(&self, file: ObjectHandleAttachment<u32>) -> Result<(), c_int> {
        let status = posix_client()
            .map_err(map_posix_client_error)?
            .fstat(file)
            .map_err(map_posix_client_error)?;
        if status.mode & 0o170000 != 0o100000 {
            return Err(ENOEXEC);
        }
        Ok(())
    }
    fn validate_captured(&self, _: shared::Source<'_>, _: &[u8]) -> Result<(), c_int> {
        // exec replaces an image inside the caller's current security domain;
        // it cannot adopt a package identity or add application capabilities.
        Ok(())
    }
    fn entropy(&self, output: &mut [u8]) -> Result<(), c_int> {
        let count = syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::RandomFill,
            output.as_mut_ptr() as u64,
            output.len() as u64,
        ))?;
        if count != output.len() as u64 {
            return Err(EIO);
        }
        Ok(())
    }
    fn create_image(&self, length: usize) -> Result<u32, c_int> {
        let raw = syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryObjectCreate,
            length as u64,
            mnu_abi::MEMORY_OBJECT_RESIZABLE,
        ))?;
        u32::try_from(raw)
            .ok()
            .filter(|handle| *handle != 0)
            .ok_or(EIO)
    }
    fn write_at(&self, image: u32, bytes: &[u8], offset: usize) -> Result<usize, c_int> {
        let count = syscall_errno(syscall::raw_syscall4(
            syscall::SyscallNumber::HandleWriteAt,
            image as u64,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            offset as u64,
        ))?;
        usize::try_from(count).map_err(|_| EIO)
    }
    fn readonly_image(&self, image: u32) -> Result<u32, c_int> {
        let raw = syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::HandleDuplicate,
            image as u64,
            posix_protocol::CHECK_EXECUTABLE_RIGHTS,
        ))?;
        u32::try_from(raw)
            .ok()
            .filter(|handle| *handle != 0)
            .ok_or(EIO)
    }
}

pub(super) fn with_image(
    image: u32,
    inputs: &exec_inputs::Inputs,
    identity: mochios_posix_client::process_image::Identity,
    operation: impl FnOnce(
        u32,
        Option<mochios_posix_client::process_image::Executable>,
        &[u8],
        &[u8],
        &[u8],
    ) -> Result<(), c_int>,
) -> Result<(), c_int> {
    let backend = Runtime;
    if !shared::needs_preparation(&backend, image)? {
        return operation(image, None, &[], &[], &[]);
    }
    io_resources::with(
        || Ok(Preparation::<Runtime>::default()),
        |preparation| {
            let prepared = preparation.prepare(
                &backend,
                image,
                Environment {
                    library_path: inputs.environment(b"LD_LIBRARY_PATH"),
                    preload: inputs.environment(b"LD_PRELOAD"),
                    audit: inputs.environment(b"LD_AUDIT"),
                },
                identity,
            )?;
            operation(
                prepared.image,
                prepared.executable,
                prepared.lifecycle,
                prepared.tls,
                prepared.indirect,
            )
        },
    )
}
