//! Static ELF TLS is owned by the C runtime, never by the native kernel.
use super::{
    ENOENT, ENOEXEC, EOVERFLOW, NATIVE_READ_WRITE, Ordering, PAGE_SIZE, ThreadControl,
    address_space, auxiliary, c_int, syscall, user_copy,
};
use mochios_posix_client::static_tls::{
    self as policy,
    modules::{InitializeError, Plan},
};
#[path = "tlsdesc.rs"]
mod tlsdesc;

fn image() -> Result<Option<policy::Template>, c_int> {
    let Some(vector) = auxiliary::vector() else {
        // A native Rust entry may attach libc without entering _start_c. Its
        // compiler uses its own TLS ABI; libc still needs a unique empty TCB.
        return Ok(None);
    };
    let table = vector.lookup(3)?;
    let stride = vector.lookup(4)?;
    let count = vector.lookup(5)?;
    // The native container is fixed-address, but AT_PHDR may describe the
    // original unrebased program. AT_BASE describes an interpreter, not this
    // program's bias. Absent optional loader metadata means fixed-address.
    let bias = match vector.lookup(mochios_posix_client::process_image::AT_IMAGE_LOAD_BIAS as usize)
    {
        Ok(bias) => bias,
        Err(ENOENT) => 0,
        Err(error) => return Err(error),
    };
    policy::template(table, stride, count, bias, |address, bytes| {
        user_copy::read(address as *const u8, bytes)
    })
    .map_err(|error| match error {
        policy::Error::InvalidImage => ENOEXEC,
        policy::Error::Read(error) => error,
    })
}

struct Mapping {
    base: usize,
    size: usize,
}
impl Drop for Mapping {
    fn drop(&mut self) {
        let _ = syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryUnmap,
            self.base as u64,
            self.size as u64,
        );
    }
}

/// Prepare before native ThreadCreate, including all AS-limit admission and
/// fallible copies. The child never starts with an uninitialized template.
pub(super) fn allocate(control: &ThreadControl) -> Result<(), c_int> {
    tlsdesc::retain();
    core::hint::black_box(__mochios_static_tls_v1 as extern "C" fn() -> u64);
    core::hint::black_box(
        __tls_get_addr as unsafe extern "C" fn(*const TlsIndex) -> *mut core::ffi::c_void,
    );
    if let Some(vector) = auxiliary::vector() {
        match vector.lookup(mochios_posix_client::process_image::AT_TLS_IMAGE as usize) {
            Ok(base) => {
                use policy::image::{self, Error};
                const MAXIMUM: usize = mnu_abi::process_image::MAX_STACK_BYTES;
                let metadata_error = |error| match error {
                    Error::Invalid => ENOEXEC,
                    Error::TooLarge => super::E2BIG,
                    Error::Read(e) => e,
                };
                let (count, size) = image::workspace(
                    base,
                    mochios_posix_client::startup_metadata::MAX_BYTES,
                    |a, b| user_copy::read(a as *const u8, b),
                )
                .map_err(metadata_error)?;
                if size > MAXIMUM {
                    let length = count
                        .checked_mul(core::mem::size_of::<Option<policy::Template>>())
                        .ok_or(super::E2BIG)?;
                    let mut storage = super::startup_storage::Buffer::new(length)?;
                    let pointer = storage
                        .bytes_mut()
                        .as_mut_ptr()
                        .cast::<Option<policy::Template>>();
                    // SAFETY: aligned, fresh private VM storage is initialized
                    // before any typed reference. No template pointer escapes.
                    let templates = unsafe {
                        for i in 0..count {
                            pointer.add(i).write(None);
                        }
                        core::slice::from_raw_parts_mut(pointer, count)
                    };
                    let count = image::decode(
                        base,
                        mochios_posix_client::startup_metadata::MAX_BYTES,
                        templates,
                        |a, b| user_copy::read(a as *const u8, b),
                    )
                    .map_err(metadata_error)?;
                    return allocate_templates(control, &templates[..count]);
                }
                let mut templates = [None; (MAXIMUM - image::HEADER_BYTES) / image::MODULE_BYTES];
                let count = image::decode(base, MAXIMUM, &mut templates, |address, bytes| {
                    user_copy::read(address as *const u8, bytes)
                })
                .map_err(|error| match error {
                    Error::Invalid => ENOEXEC,
                    Error::TooLarge => super::E2BIG,
                    Error::Read(error) => error,
                })?;
                return allocate_templates(control, &templates[..count]);
            }
            Err(ENOENT) => {}
            Err(error) => return Err(error),
        }
    }
    allocate_templates(control, &[image()?])
}

/// Startup-contract marker; never an execution or capability authorization.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __mochios_static_tls_v1() -> u64 {
    1
}

pub(super) fn allocate_templates(
    control: &ThreadControl,
    templates: &[Option<policy::Template>],
) -> Result<(), c_int> {
    let plan = Plan::new(templates, PAGE_SIZE).ok_or(EOVERFLOW)?;
    let layout = plan.layout();
    let base =
        address_space::current()?.map(0, layout.mapping_size as u64, NATIVE_READ_WRITE, 0, 0, 0)?
            as usize;
    let mapping = Mapping {
        base,
        size: layout.mapping_size,
    };
    let thread_pointer = plan
        .initialize_zeroed(
            base,
            mapping.size,
            |address, bytes| user_copy::read(address as *const u8, bytes),
            |address, bytes| user_copy::write(address as *mut u8, bytes),
        )
        .map_err(|error| match error {
            InitializeError::InvalidMapping => EOVERFLOW,
            InitializeError::Read(error) | InitializeError::Write(error) => error,
        })?;
    control
        .tls_mapping_size
        .store(mapping.size, Ordering::Relaxed);
    control
        .tls_mapping_base
        .store(mapping.base, Ordering::Relaxed);
    control
        .thread_local_base
        .store(thread_pointer as u64, Ordering::Release);
    core::mem::forget(mapping);
    Ok(())
}

pub(super) fn activate(control: &ThreadControl) -> Result<(), c_int> {
    syscall::thread_local::set_base(control.thread_local_base.load(Ordering::Acquire))
        .map_err(|error| super::map_kernel_errno(error.raw()))
}

#[repr(C)]
pub struct TlsIndex {
    pub module: usize,
    pub offset: usize,
}

pub(super) fn resolve(control: &ThreadControl, index: TlsIndex) -> Option<usize> {
    let base = control.tls_mapping_base.load(Ordering::Acquire);
    let size = control.tls_mapping_size.load(Ordering::Relaxed);
    let tp = control.thread_local_base.load(Ordering::Acquire) as usize;
    if base == 0 || tp == 0 || size > isize::MAX as usize || base.checked_add(size).is_none() {
        return None;
    }
    // SAFETY: the calling thread's registered control owns this mapping until
    // native thread retirement. It was initialized before the TP was published.
    // DTV reads are bounded; a C caller must preserve its runtime TLS mapping.
    let mapping = unsafe { core::slice::from_raw_parts(base as *const u8, size) };
    policy::dtv::address(mapping, base, tp, index.module, index.offset)
}

/// ELF TLS ABI: index must point to a readable module/offset pair supplied by
/// compiler-generated code. The runtime owns the current thread's TLS mapping.
#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub unsafe extern "C" fn __tls_get_addr(index: *const TlsIndex) -> *mut core::ffi::c_void {
    if index.is_null() {
        return core::ptr::null_mut();
    }
    let index = unsafe { index.read_unaligned() };
    super::current_thread_control()
        .and_then(|(_, control)| resolve(control, index))
        .map_or(core::ptr::null_mut(), |address| {
            address as *mut core::ffi::c_void
        })
}
