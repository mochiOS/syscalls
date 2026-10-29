//! Capture the full RELRO transaction before application resolver callbacks.
use super::*;
use mochios_posix_client::relocation_protection::{self as policy, Error, Image};
static PROTECTIONS: policy::State = policy::State::new();
static SNAPSHOT_BASE: AtomicUsize = AtomicUsize::new(0);
static SNAPSHOT_CAPACITY: AtomicUsize = AtomicUsize::new(0);
struct Snapshot {
    base: usize,
    capacity: usize,
}
impl Drop for Snapshot {
    fn drop(&mut self) {
        SNAPSHOT_CAPACITY.store(0, Ordering::Relaxed);
        SNAPSHOT_BASE.store(0, Ordering::Release);
        // SAFETY: this owner consumed the exact fresh mapping with into_raw.
        unsafe { startup_storage::Buffer::release(self.base, self.capacity) };
    }
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __mochios_relro_v1() -> u64 {
    1
}
fn error(e: Error<c_int>) -> c_int {
    match e {
        Error::Read(e) | Error::Relocate(e) | Error::Protect(e) => e,
        Error::TooLarge => E2BIG,
        _ => ENOEXEC,
    }
}
pub(super) fn status() -> Result<bool, c_int> {
    PROTECTIONS.status().map_err(error)
}
fn protect(range: policy::Range, access: u64) -> Result<(), c_int> {
    syscall_errno(syscall::raw_syscall3(
        syscall::SyscallNumber::MemoryProtect,
        range.address,
        range.length,
        access,
    ))
    .map(|_| ())
}
struct Writable<'a, 'b> {
    image: &'a Image<'b>,
    started: usize,
}
impl Drop for Writable<'_, '_> {
    fn drop(&mut self) {
        // A failed native edit may be partial. Include the attempted range,
        // restore every earlier one, and retain the original startup error.
        for range in self.image.writable_ranges().take(self.started) {
            let _ = protect(range, mnu_abi::MEMORY_ACCESS_READ);
        }
    }
}
pub(super) fn initialize(address: usize) -> Result<bool, c_int> {
    let maximum = mochios_posix_client::startup_metadata::MAX_BYTES;
    let length = policy::length(address as u64, maximum, |a, b| {
        user_copy::read(a as *const u8, b)
    })
    .map_err(error)?;
    let mut storage = startup_storage::Buffer::new(length)?;
    let length = policy::capture(address as u64, maximum, storage.bytes_mut(), |a, b| {
        user_copy::read(a as *const u8, b)
    })
    .map_err(error)?;
    let image = Image::parse(&storage.bytes()[..length]).map_err(error)?;
    let inner = address.checked_add(image.inner_offset()).ok_or(ENOEXEC)?;
    SNAPSHOT_BASE
        .compare_exchange(
            0,
            storage.bytes().as_ptr() as usize,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| ENOEXEC)?;
    SNAPSHOT_CAPACITY.store(storage.capacity(), Ordering::Relaxed);
    let (base, capacity) = storage.into_raw();
    let _snapshot = Snapshot { base, capacity };
    // SAFETY: this exact fresh private mapping remains owned until the
    // transaction returns. Its address stays recorded if C abandons the frame.
    let bytes = unsafe { core::slice::from_raw_parts(base as *const u8, length) };
    let image = Image::parse(bytes).map_err(error)?;
    let mut writable = Writable {
        image: &image,
        started: 0,
    };
    PROTECTIONS
        .apply_with_writable(
            &image,
            |plan| {
                let captured = plan.indirect();
                with_captured(
                    inner,
                    |a, b| {
                        let at = usize::try_from(a)
                            .ok()
                            .and_then(|n| n.checked_sub(inner))
                            .ok_or(EFAULT)?;
                        let end = at.checked_add(b.len()).ok_or(EFAULT)?;
                        b.copy_from_slice(captured.get(at..end).ok_or(EFAULT)?);
                        Ok(())
                    },
                    |captured| {
                        // Every fixup is captured and validated before the first
                        // permission change; no executable page is promoted.
                        for range in plan.writable_ranges() {
                            writable.started += 1;
                            protect(
                                range,
                                mnu_abi::MEMORY_ACCESS_READ | mnu_abi::MEMORY_ACCESS_WRITE,
                            )?;
                        }
                        apply(captured)
                    },
                )
                .map(|_| ())
            },
            |range| protect(range, mnu_abi::MEMORY_ACCESS_READ),
        )
        .map_err(error)?;
    writable.started = 0;
    Ok(true)
}
