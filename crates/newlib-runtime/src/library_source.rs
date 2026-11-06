//! Libc's same-domain library reader. File access uses the caller's POSIX
//! roots; captured bytes go to the common broker over an explicit RAM Handle.
use super::*;
use core::cell::Cell;
use mochios_posix_client::image_preparation::{Backend, Source};
use sha2::{Digest, Sha256};

#[derive(Default)]
pub(super) struct Reader {
    pub root: Cell<Option<(u64, u64)>>,
    pub files: Cell<library_identity::Files>,
}

// Allocation, reference ownership and callback boundaries are the same as the
// execution reader. Unlike same-domain exec preparation, every captured DSO
// is authenticated immediately, before any running-process VM installation.
unsafe impl Backend for Reader {
    fn critical<T>(f: impl FnOnce() -> T) -> T {
        exec_image::Runtime::critical(f)
    }
    fn allocate(n: usize) -> *mut u8 {
        exec_image::Runtime::allocate(n)
    }
    unsafe fn deallocate(p: *mut u8) {
        unsafe { exec_image::Runtime::deallocate(p) };
    }
    fn close(handle: u32) {
        exec_image::Runtime::close(handle);
    }
    fn read_at(&self, handle: u32, bytes: &mut [u8], offset: usize) -> Result<usize, c_int> {
        exec_image::Runtime.read_at(handle, bytes, offset)
    }
    fn open_library(&self, path: &[u8]) -> Result<ObjectHandleAttachment<u32>, c_int> {
        exec_image::Runtime.open_library(path)
    }
    fn validate_library(&self, file: ObjectHandleAttachment<u32>) -> Result<(), c_int> {
        let status = posix_client()
            .map_err(map_posix_client_error)?
            .fstat(file)
            .map_err(map_posix_client_error)?;
        if status.mode & 0o170000 != 0o100000 {
            return Err(ENOEXEC);
        }
        let mut files = self.files.get();
        if !files.insert((status.device, status.inode)) {
            return Err(ENOTSUP);
        }
        self.files.set(files);
        if self.root.get().is_none() {
            self.root.set(Some((status.device, status.inode)));
        }
        Ok(())
    }
    fn validate_captured(&self, _: Source<'_>, bytes: &[u8]) -> Result<(), c_int> {
        authenticate(bytes)
    }
    fn entropy(&self, bytes: &mut [u8]) -> Result<(), c_int> {
        exec_image::Runtime.entropy(bytes)
    }
    fn create_image(&self, n: usize) -> Result<u32, c_int> {
        exec_image::Runtime.create_image(n)
    }
    fn write_at(&self, handle: u32, bytes: &[u8], offset: usize) -> Result<usize, c_int> {
        exec_image::Runtime.write_at(handle, bytes, offset)
    }
    fn readonly_image(&self, handle: u32) -> Result<u32, c_int> {
        exec_image::Runtime.readonly_image(handle)
    }
}

#[derive(Default)]
struct Capture {
    writer: u32,
    reader: u32,
}
impl Drop for Capture {
    fn drop(&mut self) {
        let _delivery = defer_native_delivery();
        for handle in [self.writer, self.reader] {
            if handle != 0 {
                close_object_handle(handle);
            }
        }
    }
}

fn authenticate(source: &[u8]) -> Result<(), c_int> {
    use mochios_capability_protocol::library_image as wire;
    io_resources::with(
        || Ok(Capture::default()),
        |capture| {
            Reader::critical(|| {
                capture.writer = exec_image::Runtime.create_image(source.len())?;
                Ok::<_, c_int>(())
            })?;
            let mut offset = 0;
            while offset < source.len() {
                let end = source.len().min(offset + 64 * 1024);
                let n =
                    exec_image::Runtime.write_at(capture.writer, &source[offset..end], offset)?;
                if n == 0 || n > end - offset {
                    return Err(EIO);
                }
                offset += n;
            }
            Reader::critical(|| {
                let handle = syscall_errno(syscall::raw_syscall2(
                    syscall::SyscallNumber::HandleDuplicate,
                    capture.writer as u64,
                    mnu_abi::HANDLE_RIGHT_READ
                        | mnu_abi::HANDLE_RIGHT_MAP
                        | mnu_abi::HANDLE_RIGHT_TRANSFER,
                ))?;
                capture.reader = u32::try_from(handle).ok().filter(|h| *h != 0).ok_or(EIO)?;
                close_object_handle(capture.writer);
                capture.writer = 0;
                Ok::<_, c_int>(())
            })?;
            let endpoint = syscall_errno(syscall::raw_syscall2(
                syscall::SyscallNumber::FindProcessByName,
                CAPABILITY_SERVICE_NAME.as_ptr() as u64,
                CAPABILITY_SERVICE_NAME.len() as u64,
            ))?;
            if endpoint == 0 {
                return Err(ENOENT);
            }
            let mut request = [0; wire::REQUEST_LEN];
            wire::encode(source.len() as u64, &mut request).map_err(|_| EINVAL)?;
            let mut handles = mnu_abi::IpcObjectHandles::default();
            handles.count = 1;
            handles.handles[0] = mnu_abi::IpcObjectHandle {
                handle: capture.reader,
                reserved: 0,
                rights: mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_MAP,
            };
            let mut reply = [0; wire::REPLY_LEN];
            // Drain any reply references before delivery can abandon this frame.
            let _delivery = defer_native_delivery();
            let result = syscall_errno(syscall::raw_syscall6(
                syscall::SyscallNumber::IpcCallObjectHandles,
                endpoint,
                request.as_ptr() as u64,
                request.len() as u64,
                reply.as_mut_ptr() as u64,
                reply.len() as u64,
                &mut handles as *mut _ as u64,
            ));
            let count = (handles.count as usize).min(handles.handles.len());
            for (index, h) in handles.handles[..count].iter().enumerate() {
                if h.handle != 0
                    && h.handle != capture.reader
                    && !handles.handles[..index]
                        .iter()
                        .any(|old| old.handle == h.handle)
                {
                    close_object_handle(h.handle);
                }
            }
            if result? as u32 as usize != reply.len()
                || handles.count != 0
                || handles.delivery_flags != 0
            {
                return Err(EIO);
            }
            let (status, digest) = wire::decode_reply(&reply).map_err(|_| EIO)?;
            if status != 0 {
                return Err(i64::try_from(status).map(map_kernel_errno).unwrap_or(EIO));
            }
            if Sha256::digest(source).as_slice() != digest {
                return Err(EACCES);
            }
            Ok(())
        },
    )
}
