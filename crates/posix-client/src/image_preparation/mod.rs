//! Shared user-space loader orchestration. Handles and allocations stay in an
//! externally owned Preparation so callback-aware runtimes can track its lifetime.
//! Parsing, search, relocation, initial TLS and lifecycle metadata are common;
//! the backend supplies explicit access authority and resource mechanisms.
use crate as mochios_posix_client;
use crate::newlib_errno::*;
use crate::protocol as posix_protocol;
use core::{ffi::c_int, marker::PhantomData, ptr};
mod dependencies;
pub mod scoped;

const PAGE_SIZE: usize = 4096;

#[derive(Clone, Copy, Default)]
pub struct Environment<'a> {
    pub library_path: Option<&'a [u8]>,
    pub preload: Option<&'a [u8]>,
    pub audit: Option<&'a [u8]>,
}

/// Borrowed loader output. Authorization and image installation remain with
/// the caller; this module never grants execution rights or changes a process.
pub struct Prepared<'a> {
    pub image: u32,
    pub executable: Option<crate::process_image::Executable>,
    pub lifecycle: &'a [u8],
    pub tls: &'a [u8],
}

/// Selection metadata for an immutable input captured by this preparation.
/// A pathname identifies a search candidate, never authenticates its contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source<'a> {
    Root,
    Dependency { needed: &'a [u8], path: &'a [u8] },
}

/// Explicit resource access, independent of libc globals and broker policy.
/// Status values are positive newlib errno values, translated at this boundary.
/// Library opens use read-only, nonblocking access under the selected context.
///
/// # Safety
/// `allocate` returns null or fresh storage of at least the requested size,
/// aligned to 16 bytes. `deallocate` frees those allocations and accepts null.
/// Their implementation and lifetime must not depend on a backend instance.
/// `critical` must defer callbacks capable of abandoning Rust frames until
/// resource acquisition/publication or release finishes. Ordinary Rust-only
/// callers may invoke the closure directly. Each returned Handle is a fresh
/// owned reference, closed by `close`; readonly_image grants only READ/TRANSFER.
pub unsafe trait Backend {
    fn critical<T>(operation: impl FnOnce() -> T) -> T;
    fn allocate(length: usize) -> *mut u8;
    /// # Safety
    /// The pointer is null or a live allocation returned by Self::allocate.
    unsafe fn deallocate(pointer: *mut u8);
    fn close(handle: u32);
    fn read_at(&self, image: u32, output: &mut [u8], offset: usize) -> Result<usize, c_int>;
    fn open_library(&self, path: &[u8]) -> Result<crate::ObjectHandleAttachment<u32>, c_int>;
    fn validate_library(&self, file: crate::ObjectHandleAttachment<u32>) -> Result<(), c_int>;
    /// Check the exact captured input before parsing or emitting an image.
    /// Replacement within the caller's existing security domain may accept
    /// its own input. A launcher granting a new identity/capabilities must
    /// bind every input to its approved package policy here; a later pathname
    /// read cannot authenticate these bytes. Errors abort preparation intact.
    fn validate_captured(&self, source: Source<'_>, bytes: &[u8]) -> Result<(), c_int>;
    fn entropy(&self, output: &mut [u8]) -> Result<(), c_int>;
    fn create_image(&self, length: usize) -> Result<u32, c_int>;
    fn write_at(&self, image: u32, bytes: &[u8], offset: usize) -> Result<usize, c_int>;
    fn readonly_image(&self, image: u32) -> Result<u32, c_int>;
}

const MAX_IMAGE: usize = mnu_abi::exec::MAX_CAPTURED_IMAGE_BYTES;

struct Buffer<B: Backend> {
    pointer: *mut u8,
    length: usize,
    capacity: usize,
    backend: PhantomData<fn() -> B>,
}
impl<B: Backend> Default for Buffer<B> {
    fn default() -> Self {
        Self {
            pointer: ptr::null_mut(),
            length: 0,
            capacity: 0,
            backend: PhantomData,
        }
    }
}
impl<B: Backend> Buffer<B> {
    fn bytes(&self) -> &[u8] {
        if self.length == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(self.pointer, self.length) }
        }
    }
    fn slots<T>(&mut self, count: usize) -> Result<*mut T, c_int> {
        let bytes = count.checked_mul(core::mem::size_of::<T>()).ok_or(ENOMEM)?;
        if core::mem::align_of::<T>() > 16 {
            return Err(EINVAL);
        }
        self.reserve(bytes)?;
        self.length = bytes;
        Ok(self.pointer.cast())
    }
    fn reserve(&mut self, required: usize) -> Result<(), c_int> {
        if required > MAX_IMAGE {
            return Err(EFBIG);
        }
        if required <= self.capacity {
            return Ok(());
        }
        let capacity = required
            .checked_next_power_of_two()
            .unwrap_or(MAX_IMAGE)
            .min(MAX_IMAGE);
        B::critical(|| {
            let pointer = B::allocate(capacity);
            if pointer.is_null() {
                return Err(ENOMEM);
            }
            unsafe {
                ptr::write_bytes(pointer, 0, capacity);
                if self.length != 0 {
                    ptr::copy_nonoverlapping(self.pointer, pointer, self.length);
                }
                B::deallocate(self.pointer);
            }
            self.pointer = pointer;
            self.capacity = capacity;
            Ok(())
        })
    }
}
impl<B: Backend> Drop for Buffer<B> {
    fn drop(&mut self) {
        B::critical(|| unsafe { B::deallocate(self.pointer) });
    }
}

/// Buffers and native references belong to this owner before any blocking I/O.
/// Use a fresh owner for each image; failed preparations cannot be reused.
/// C runtimes must register it with their callback-abandonment resource chain.
pub struct Preparation<B: Backend> {
    source: Buffer<B>,
    output: Buffer<B>,
    dependencies: dependencies::Dependencies<B>,
    handle: u32,
    executable: Option<crate::process_image::Executable>,
    lifecycle: Buffer<B>,
    tls: Buffer<B>,
    started: bool,
}
impl<B: Backend> Default for Preparation<B> {
    fn default() -> Self {
        Self {
            source: Buffer::default(),
            output: Buffer::default(),
            dependencies: dependencies::Dependencies::default(),
            handle: 0,
            executable: None,
            lifecycle: Buffer::default(),
            tls: Buffer::default(),
            started: false,
        }
    }
}
impl<B: Backend> Drop for Preparation<B> {
    fn drop(&mut self) {
        if self.handle != 0 {
            B::critical(|| B::close(self.handle));
        }
    }
}
fn read_at<B: Backend>(
    backend: &B,
    image: u32,
    output: &mut [u8],
    offset: usize,
) -> Result<usize, c_int> {
    backend.read_at(image, output, offset).and_then(|count| {
        if count <= output.len() {
            Ok(count)
        } else {
            Err(EIO)
        }
    })
}
pub fn needs_preparation<B: Backend>(backend: &B, image: u32) -> Result<bool, c_int> {
    let mut header = [0u8; 64];
    let mut read = 0;
    while read < header.len() {
        let n = read_at(backend, image, &mut header[read..], read)?;
        if n == 0 {
            break;
        }
        read += n;
    }
    if read != 64 || header[..7] != [0x7f, b'E', b'L', b'F', 2, 1, 1] {
        return Ok(false);
    }
    if header[16..18] == 3u16.to_le_bytes() {
        return Ok(true);
    }
    if header[16..18] != 2u16.to_le_bytes() {
        return Ok(false);
    }
    let offset = usize::try_from(u64::from_le_bytes(header[32..40].try_into().unwrap()))
        .map_err(|_| ENOEXEC)?;
    let stride = usize::from(u16::from_le_bytes(header[54..56].try_into().unwrap()));
    let count = usize::from(u16::from_le_bytes(header[56..58].try_into().unwrap()));
    if stride < 56
        || count == 0
        || offset
            .checked_add(count.checked_mul(stride).ok_or(ENOEXEC)?)
            .is_none_or(|end| end > MAX_IMAGE)
    {
        return Err(ENOEXEC);
    }
    for index in 0..count {
        let mut entry = [0; 56];
        let mut done = 0;
        while done < entry.len() {
            let amount = read_at(
                backend,
                image,
                &mut entry[done..],
                offset + index * stride + done,
            )?;
            if amount == 0 {
                return Err(ENOEXEC);
            }
            done += amount;
        }
        if matches!(u32::from_le_bytes(entry[..4].try_into().unwrap()), 2 | 3) {
            return Ok(true);
        }
    }
    Ok(false)
}
impl<B: Backend> Preparation<B> {
    fn build(
        &mut self,
        backend: &B,
        image: u32,
        environment: Environment<'_>,
        identity: mochios_posix_client::process_image::Identity,
    ) -> Result<(), c_int> {
        let mut chunk = [0u8; mnu_abi::provider::MAX_DATA_LEN];
        loop {
            let n = read_at(backend, image, &mut chunk, self.source.length)?;
            if n == 0 {
                break;
            }
            let length = self.source.length.checked_add(n).ok_or(EFBIG)?;
            self.source.reserve(length)?;
            unsafe {
                ptr::copy_nonoverlapping(
                    chunk.as_ptr(),
                    self.source.pointer.add(self.source.length),
                    n,
                )
            };
            self.source.length = length;
        }
        backend.validate_captured(Source::Root, self.source.bytes())?;
        let candidate = mochios_posix_client::pie::Pie::parse_object(self.source.bytes())
            .map_err(|_| ENOEXEC)?;
        let mut dependent = false;
        candidate
            .dependencies(|_| {
                dependent = true;
                Ok(())
            })
            .map_err(|_| ENOEXEC)?;
        let runtime = candidate.has_lifecycle_runtime().map_err(|_| ENOEXEC)?;
        let length = if candidate.is_fixed()
            || dependent
            || candidate.requires_tls_scope().map_err(|_| ENOEXEC)?
            || (runtime && candidate.validate_direct_scope_startup().is_err())
        {
            self.executable = Some(self.dependencies.build(
                self.source.bytes(),
                &mut self.output,
                &mut self.lifecycle,
                &mut self.tls,
                backend,
                environment,
                identity,
                runtime,
            )?);
            self.output.length
        } else {
            let pie =
                mochios_posix_client::pie::Pie::parse(self.source.bytes()).map_err(|_| ENOEXEC)?;
            let length = pie.output_length().map_err(|_| ENOEXEC)?;
            self.output.reserve(length)?;
            self.output.length = length;
            let mut entropy = [0u8; 8];
            backend.entropy(&mut entropy)?;
            let alignment = pie.alignment();
            let base = 0x2000_0000u64
                .checked_add(alignment - 1)
                .map(|base| base & !(alignment - 1))
                .ok_or(ENOEXEC)?;
            let slots = (64 * 1024 * 1024 / alignment).max(1);
            let bias = base
                .checked_add((u64::from_le_bytes(entropy) % slots) * alignment)
                .ok_or(ENOEXEC)?;
            self.executable = Some(pie.executable(bias).map_err(|_| ENOEXEC)?);
            let output = unsafe { core::slice::from_raw_parts_mut(self.output.pointer, length) };
            if pie.write(bias, output).map_err(|_| ENOEXEC)? != length {
                return Err(EIO);
            }
            length
        };
        B::critical(|| {
            self.handle = backend.create_image(length)?;
            if self.handle == 0 {
                return Err(EIO);
            }
            Ok(())
        })?;
        let mut offset = 0;
        while offset < length {
            let bytes = &self.output.bytes()[offset..length.min(offset + chunk.len())];
            let n = backend.write_at(self.handle, bytes, offset)?;
            if n == 0 || n > bytes.len() {
                return Err(EIO);
            }
            offset += n;
        }
        // Keep no writable/resize alias while requesting execution authority.
        B::critical(|| {
            let read = backend.readonly_image(self.handle)?;
            if read == 0 || read == self.handle {
                return Err(EIO);
            }
            B::close(self.handle);
            self.handle = read;
            Ok(())
        })
    }

    pub fn prepare(
        &mut self,
        backend: &B,
        image: u32,
        environment: Environment<'_>,
        identity: crate::process_image::Identity,
    ) -> Result<Prepared<'_>, c_int> {
        if self.started {
            return Err(EINVAL);
        }
        self.started = true;
        self.build(backend, image, environment, identity)?;
        Ok(Prepared {
            image: self.handle,
            executable: self.executable,
            lifecycle: self.lifecycle.bytes(),
            tls: self.tls.bytes(),
        })
    }
}
