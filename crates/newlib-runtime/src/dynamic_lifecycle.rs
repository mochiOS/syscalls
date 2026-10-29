//! Capture recipes before resolvers and freeze final callbacks before init.
use super::*;
use core::{cell::UnsafeCell, ptr, sync::atomic::AtomicU8};
use mochios_posix_client::lifecycle_image::{Error, Image, State, deferred};
const MAXIMUM: usize = mnu_abi::process_image::MAX_STACK_BYTES;
const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const PREPARED: u8 = 2;
const RESOLVING: u8 = 3;
const READY: u8 = 4;
const FAILED: u8 = 5;
const ABSENT: u8 = 6;
static PHASE: AtomicU8 = AtomicU8::new(EMPTY);
static LENGTH: AtomicUsize = AtomicUsize::new(0);
static ADDRESS: AtomicUsize = AtomicUsize::new(0);
static CAPACITY: AtomicUsize = AtomicUsize::new(0);
static OUTPUT: AtomicUsize = AtomicUsize::new(0);
static OUTPUT_CAPACITY: AtomicUsize = AtomicUsize::new(0);
static LIFECYCLE: State = State::new();
#[repr(align(8))]
struct Snapshot(UnsafeCell<[u8; MAXIMUM]>);
// Only the thread winning EMPTY->WRITING or PREPARED->RESOLVING writes. READY
// publishes immutable bytes. No reference or owner escapes this module, and
// no lock is held while application callbacks run. fork inherits its own COW.
unsafe impl Sync for Snapshot {}
static SNAPSHOT: Snapshot = Snapshot(UnsafeCell::new([0; MAXIMUM]));

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __mochios_lifecycle_v1() -> u64 {
    1
}
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __mochios_lifecycle_v2() -> u64 {
    2
}

fn read(address: u64, bytes: &mut [u8]) -> Result<(), c_int> {
    let address = usize::try_from(address).map_err(|_| EFAULT)?;
    user_copy::read(address as *const u8, bytes)
}
fn error(error: Error<c_int>) -> c_int {
    match error {
        Error::Read(error) => error,
        Error::Invalid => ENOEXEC,
        Error::TooLarge => E2BIG,
    }
}
fn call(address: u64) -> Result<(), c_int> {
    let address = usize::try_from(address).map_err(|_| ENOEXEC)?;
    // SAFETY: v1 was validated by the exec producer; v2 values were checked
    // against captured executable LOADs after resolvers and before callbacks.
    let function: unsafe extern "C" fn() = unsafe { core::mem::transmute(address) };
    unsafe { function() };
    Ok(())
}

/// Must precede every resolver. Even absence is captured so a resolver cannot
/// introduce different lifecycle metadata through the original aux vector.
pub(super) fn prepare() -> Result<bool, c_int> {
    match PHASE.load(Ordering::Acquire) {
        PREPARED | READY => return Ok(true),
        ABSENT => return Ok(false),
        EMPTY => {}
        _ => return Err(ENOEXEC),
    }
    let address = match auxiliary::vector() {
        None => None,
        Some(vector) => {
            match vector.lookup(mochios_posix_client::process_image::AT_LIFECYCLE_IMAGE as usize) {
                Ok(address) => Some(address),
                Err(ENOENT) => None,
                Err(error) => return Err(error),
            }
        }
    };
    let Some(address) = address else {
        PHASE
            .compare_exchange(EMPTY, ABSENT, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ENOEXEC)?;
        return Ok(false);
    };
    let size = deferred::encoded_length(
        address as u64,
        mochios_posix_client::startup_metadata::MAX_BYTES,
        read,
    )
    .map_err(error)?;
    let mut bytes = [0; MAXIMUM];
    let mut large = if size > MAXIMUM {
        Some(startup_storage::Buffer::new(size)?)
    } else {
        None
    };
    let target = large.as_mut().map(|b| b.bytes_mut()).unwrap_or(&mut bytes);
    let length = deferred::capture(
        address as u64,
        mochios_posix_client::startup_metadata::MAX_BYTES,
        target,
        read,
    )
    .map_err(error)?;
    // Allocate all output storage before the first resolver. Nothing acquired
    // after a resolver installs callbacks can be lost to a nonlocal exit.
    let flat = if u32::from_le_bytes(target[8..12].try_into().unwrap()) == deferred::VERSION {
        deferred::Plan::parse::<c_int>(&target[..length])
            .map_err(error)?
            .flat_length()
    } else {
        0
    };
    let output = if flat > MAXIMUM {
        Some(startup_storage::Buffer::new(flat)?)
    } else {
        None
    };
    PHASE
        .compare_exchange(EMPTY, WRITING, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| ENOEXEC)?;
    // SAFETY: the winning writer exclusively owns the internal buffer; bounds
    // were checked by capture, and source stack and static storage are disjoint.
    let (base, capacity) = if let Some(storage) = large {
        storage.into_raw()
    } else {
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), SNAPSHOT.0.get().cast::<u8>(), length) };
        (SNAPSHOT.0.get() as usize, 0)
    };
    if let Some(output) = output {
        let (base, capacity) = output.into_raw();
        OUTPUT.store(base, Ordering::Relaxed);
        OUTPUT_CAPACITY.store(capacity, Ordering::Relaxed);
    }
    ADDRESS.store(base, Ordering::Relaxed);
    CAPACITY.store(capacity, Ordering::Relaxed);
    LENGTH.store(length, Ordering::Relaxed);
    PHASE.store(PREPARED, Ordering::Release);
    Ok(true)
}

fn resolve() -> Result<(), c_int> {
    if PHASE.load(Ordering::Acquire) == READY {
        return Ok(());
    }
    PHASE
        .compare_exchange(PREPARED, RESOLVING, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| ENOEXEC)?;
    struct Attempt;
    impl Drop for Attempt {
        fn drop(&mut self) {
            PHASE.store(FAILED, Ordering::Release);
        }
    }
    let attempt = Attempt;
    let length = LENGTH.load(Ordering::Relaxed);
    let mut output = [0; MAXIMUM];
    let resolved = {
        // SAFETY: only the resolving winner reads this bounded prepared plan.
        // No callbacks execute and no writable reference is outstanding.
        let bytes = unsafe {
            core::slice::from_raw_parts(ADDRESS.load(Ordering::Relaxed) as *const u8, length)
        };
        if u32::from_le_bytes(bytes[8..12].try_into().unwrap()) == deferred::VERSION {
            let plan = deferred::Plan::parse::<c_int>(bytes).map_err(error)?;
            let address = OUTPUT.load(Ordering::Relaxed);
            let target = if plan.flat_length() > MAXIMUM {
                if address == 0 || OUTPUT_CAPACITY.load(Ordering::Relaxed) < plan.flat_length() {
                    return Err(ENOEXEC);
                }
                // SAFETY: prepare retained this private, fully bounded output
                // mapping. It is disjoint from the immutable plan mapping.
                unsafe { core::slice::from_raw_parts_mut(address as *mut u8, plan.flat_length()) }
            } else {
                &mut output[..]
            };
            Some(plan.resolve(target, read).map_err(error)?)
        } else {
            None
        }
    };
    if let Some(length) = resolved {
        // SAFETY: the plan borrow ended; this winner still has exclusive write
        // access. From READY onward all callers only read the resulting image.
        let old = ADDRESS.load(Ordering::Relaxed);
        let old_capacity = CAPACITY.load(Ordering::Relaxed);
        let (base, capacity) = if length > MAXIMUM {
            (
                OUTPUT.swap(0, Ordering::Relaxed),
                OUTPUT_CAPACITY.swap(0, Ordering::Relaxed),
            )
        } else {
            unsafe {
                ptr::copy_nonoverlapping(output.as_ptr(), SNAPSHOT.0.get().cast::<u8>(), length)
            };
            (SNAPSHOT.0.get() as usize, 0)
        };
        ADDRESS.store(base, Ordering::Relaxed);
        CAPACITY.store(capacity, Ordering::Relaxed);
        LENGTH.store(length, Ordering::Relaxed);
        if old_capacity != 0 {
            unsafe { startup_storage::Buffer::release(old, old_capacity) };
        }
    }
    PHASE.store(READY, Ordering::Release);
    core::mem::forget(attempt);
    Ok(())
}
fn image() -> Result<Image, c_int> {
    Image::read(
        ADDRESS.load(Ordering::Acquire) as u64,
        LENGTH.load(Ordering::Acquire),
        read,
    )
    .map_err(error)
}
pub(super) fn initialize() -> Result<bool, c_int> {
    if PHASE.load(Ordering::Acquire) == ABSENT {
        return Ok(false);
    }
    resolve()?;
    let image = image()?;
    LIFECYCLE.initialize(&image, read, call).map_err(error)?;
    Ok(true)
}
pub(super) fn finalize() -> Result<bool, c_int> {
    match PHASE.load(Ordering::Acquire) {
        EMPTY | ABSENT => return Ok(false),
        WRITING | PREPARED | RESOLVING => return Ok(true), // no initializers have begun
        READY => {}
        _ => return Err(ENOEXEC),
    }
    LIFECYCLE.finalize(&image()?, read, call).map_err(error)?;
    Ok(true)
}
