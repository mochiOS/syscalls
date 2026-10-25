//! Static ELF TLS is owned by the C runtime, never by the native kernel.
use super::{
    ENOEXEC, EOVERFLOW, NATIVE_READ_WRITE, Ordering, PAGE_SIZE, ThreadControl, address_space,
    auxiliary, c_int, syscall, user_copy,
};
use mochios_posix_client::static_tls::{self as policy, Layout};

fn image() -> Result<Option<policy::Template>, c_int> {
    let Some(vector) = auxiliary::vector() else {
        // A native Rust entry may attach libc without entering _start_c. Its
        // compiler uses its own TLS ABI; libc still needs a unique empty TCB.
        return Ok(None);
    };
    let table = vector.lookup(3)?;
    let stride = vector.lookup(4)?;
    let count = vector.lookup(5)?;
    // Native exec consumes fixed-address images. Static PIE preparation in
    // posix-client already relocates ELF headers before native image creation.
    policy::template(table, stride, count, 0, |address, bytes| {
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
    let template = image()?;
    let layout = Layout::new(template, PAGE_SIZE).ok_or(EOVERFLOW)?;
    let base =
        address_space::current()?.map(0, layout.mapping_size as u64, NATIVE_READ_WRITE, 0, 0, 0)?
            as usize;
    let mapping = Mapping {
        base,
        size: layout.mapping_size,
    };
    let placed = layout.place(base).ok_or(EOVERFLOW)?;
    // Native anonymous mappings are zero-filled, including all .tbss bytes.
    if let Some(template) = template {
        let mut offset = 0;
        let mut bytes = [0u8; 512];
        while offset < template.file_size {
            let size = bytes.len().min(template.file_size - offset);
            user_copy::read((template.source + offset) as *const u8, &mut bytes[..size])?;
            user_copy::write((placed.data + offset) as *mut u8, &bytes[..size])?;
            offset += size;
        }
    }
    user_copy::write(
        placed.thread_pointer as *mut u8,
        &placed.thread_pointer.to_ne_bytes(),
    )?;
    control
        .tls_mapping_size
        .store(mapping.size, Ordering::Relaxed);
    control
        .tls_mapping_base
        .store(mapping.base, Ordering::Relaxed);
    control
        .thread_local_base
        .store(placed.thread_pointer as u64, Ordering::Release);
    core::mem::forget(mapping);
    Ok(())
}

pub(super) fn activate(control: &ThreadControl) -> Result<(), c_int> {
    syscall::thread_local::set_base(control.thread_local_base.load(Ordering::Acquire))
        .map_err(|error| super::map_kernel_errno(error.raw()))
}
