//! Initial-image resolvers run after TLS, before constructors or main.
use super::*;
use mochios_posix_client::indirect_image::{self as policy, Captured, Error, Fixup, Region, State};
static RESOLVERS: State = State::new();
#[path = "dynamic_indirect/protection.rs"]
mod protection;
pub(super) use protection::__mochios_relro_v1;
// Per-image ownership remains discoverable if a resolver abandons its frame.
// It is never overwritten by reentry; process teardown owns any abandoned VM.
static LARGE_BASE: AtomicUsize = AtomicUsize::new(0);
static LARGE_CAPACITY: AtomicUsize = AtomicUsize::new(0);
struct LargeWorkspace {
    base: usize,
    capacity: usize,
}
impl Drop for LargeWorkspace {
    fn drop(&mut self) {
        LARGE_CAPACITY.store(0, Ordering::Relaxed);
        LARGE_BASE.store(0, Ordering::Release);
        // SAFETY: the constructor moved this exact fresh mapping into this owner.
        unsafe { startup_storage::Buffer::release(self.base, self.capacity) };
    }
}

/// Startup contract only. The producer separately authenticates every input
/// and obtains execution authority before the kernel installs the image.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __mochios_indirect_v1() -> u64 {
    1
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __mochios_indirect_v2() -> u64 {
    2
}

fn error(error: Error<c_int>) -> c_int {
    match error {
        Error::Read(error) | Error::Write(error) | Error::Resolve(error) => error,
        Error::TooLarge | Error::BufferTooSmall => E2BIG,
        Error::Invalid | Error::Reentrant | Error::Failed => ENOEXEC,
    }
}

pub(super) fn initialize() -> Result<bool, c_int> {
    if protection::status()? {
        return Ok(true);
    }
    let Some(vector) = auxiliary::vector() else {
        return Ok(false);
    };
    let address =
        match vector.lookup(mochios_posix_client::process_image::AT_INDIRECT_IMAGE as usize) {
            Ok(address) => address,
            Err(ENOENT) => return Ok(false),
            Err(error) => return Err(error),
        };
    if address < 0x400000 || address % 8 != 0 {
        return Err(ENOEXEC);
    }
    let mut magic = [0; 8];
    user_copy::read(address as *const u8, &mut magic)?;
    if u64::from_le_bytes(magic) == mochios_posix_client::relocation_protection::MAGIC {
        return protection::initialize(address);
    }
    initialize_at(address, |a, b| user_copy::read(a as *const u8, b))
}
fn initialize_at(
    address: usize,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<(), c_int>,
) -> Result<bool, c_int> {
    const MAXIMUM: usize = mnu_abi::process_image::MAX_STACK_BYTES;
    let (region_count, fixup_count, size) = policy::workspace(
        address as u64,
        mochios_posix_client::startup_metadata::MAX_BYTES,
        &mut read,
    )
    .map_err(error)?;
    if size > MAXIMUM {
        let region_bytes = region_count
            .checked_mul(core::mem::size_of::<Region>())
            .ok_or(E2BIG)?;
        let alignment = core::mem::align_of::<Fixup>();
        let fixup_offset = region_bytes
            .checked_add(alignment - 1)
            .map(|n| n & !(alignment - 1))
            .ok_or(E2BIG)?;
        let bytes = fixup_count
            .checked_mul(core::mem::size_of::<Fixup>())
            .and_then(|n| fixup_offset.checked_add(n))
            .ok_or(E2BIG)?;
        let mut storage = startup_storage::Buffer::new(bytes.max(1))?;
        let pointer = storage.bytes_mut().as_mut_ptr();
        LARGE_BASE
            .compare_exchange(0, pointer as usize, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ENOEXEC)?;
        LARGE_CAPACITY.store(storage.capacity(), Ordering::Relaxed);
        let (base, capacity) = storage.into_raw();
        let _owner = LargeWorkspace { base, capacity };
        // SAFETY: disjoint, aligned views into the fresh private mapping. Every
        // enum/bool is initialized before creating a typed Rust reference.
        let (regions, fixups) = unsafe {
            let regions = pointer.cast::<Region>();
            let fixups = pointer.add(fixup_offset).cast::<Fixup>();
            for i in 0..region_count {
                regions.add(i).write(Region::EMPTY);
            }
            for i in 0..fixup_count {
                fixups.add(i).write(Fixup::EMPTY);
            }
            (
                core::slice::from_raw_parts_mut(regions, region_count),
                core::slice::from_raw_parts_mut(fixups, fixup_count),
            )
        };
        let image = Captured::capture(
            address as u64,
            mochios_posix_client::startup_metadata::MAX_BYTES,
            regions,
            fixups,
            &mut read,
        )
        .map_err(error)?;
        return apply(&image);
    }
    // The bounded startup payload fits in the existing native entry stack.
    // Both workspaces are private; no allocation/Handle survives a resolver
    // which exits or abandons this frame with a C nonlocal jump.
    let mut regions = [Region::EMPTY; (MAXIMUM - policy::HEADER_BYTES) / policy::REGION_BYTES];
    let mut fixups = [Fixup::EMPTY; (MAXIMUM - policy::HEADER_BYTES) / policy::FIXUP_BYTES];
    let image = Captured::capture(
        address as u64,
        MAXIMUM,
        &mut regions,
        &mut fixups,
        &mut read,
    )
    .map_err(error)?;
    apply(&image)
}
fn apply(image: &Captured<'_>) -> Result<bool, c_int> {
    RESOLVERS
        .apply_with_copies(
            image,
            |address, bytes| user_copy::read(address as *const u8, bytes),
            |address| -> Result<u64, c_int> {
                // SAFETY: capture checked every resolver against the authorized
                // installed executable LOADs before the first function is invoked.
                let resolver: unsafe extern "C" fn() -> u64 =
                    unsafe { core::mem::transmute(address as usize) };
                Ok(unsafe { resolver() })
            },
            |address, bytes| user_copy::write(address as *mut u8, bytes),
        )
        .map_err(error)?;
    Ok(true)
}
