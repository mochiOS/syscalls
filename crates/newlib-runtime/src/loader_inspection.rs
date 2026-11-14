//! Process-local dynamic-linker inspection. Metadata is captured before any
//! constructor, and late groups stay protected by the existing loader lease.
use super::*;
use mochios_posix_client::loaded_objects::{self as wire, Image};
static INITIAL: AtomicUsize = AtomicUsize::new(0);
static INITIAL_LENGTH: AtomicUsize = AtomicUsize::new(0);

// The initial executable's captured default exports remain mapped until
// process teardown. Local dlopen groups do not become a global namespace.
pub(super) fn initial_symbol(name: &[u8]) -> Option<(u64, u64)> {
    let image = Image::parse(initial()).ok()?;
    (0..image.count()).find_map(|index| image.entry(index).ok()?.lookup(name))
}

/// Initial metadata was captured before constructors from the authenticated
/// startup graph. No pathname lookup or application-supplied header is trusted.
pub(super) fn initial_library(name: &[u8]) -> bool {
    let Ok(image) = Image::parse(initial()) else { return false };
    !name.is_empty() && !name.contains(&b'/') && (1..image.count())
        .any(|index| image.entry(index).is_ok_and(|entry| entry.name == name))
}

pub(super) fn initialize() -> Result<(), c_int> {
    let Some(vector) = auxiliary::vector() else {
        return Ok(());
    };
    let address =
        match vector.lookup(mochios_posix_client::process_image::AT_LOADED_OBJECTS as usize) {
            Ok(address) => address,
            Err(ENOENT) => return Ok(()),
            Err(error) => return Err(error),
        };
    let mut header = [0u8; 24];
    user_copy::read(address as *const u8, &mut header)?;
    let length = usize::try_from(u64::from_le_bytes(header[8..16].try_into().unwrap()))
        .map_err(|_| E2BIG)?;
    if !(24..=wire::MAX_BYTES).contains(&length) {
        return Err(ENOEXEC);
    }
    let mut snapshot = startup_storage::Buffer::new(length)?;
    user_copy::read(address as *const u8, snapshot.bytes_mut())?;
    Image::parse(snapshot.bytes())?;
    let (base, _) = snapshot.into_raw();
    // The initial graph lives until process exit; fork inherits its private
    // snapshot. Publication happens before constructors or pthread creation.
    INITIAL_LENGTH.store(length, Ordering::Relaxed);
    INITIAL.store(base, Ordering::Release);
    Ok(())
}
pub(super) fn initial() -> &'static [u8] {
    let base = INITIAL.load(Ordering::Acquire);
    if base == 0 {
        return &[];
    }
    // SAFETY: initialize publishes a retained, runtime-owned mapping once.
    unsafe {
        core::slice::from_raw_parts(base as *const u8, INITIAL_LENGTH.load(Ordering::Relaxed))
    }
}

#[repr(C)]
pub struct DlInfo {
    filename: *const c_char,
    base: *mut c_void,
    symbol: *const c_char,
    symbol_address: *mut c_void,
}

/// Resolve an address against actual loaded LOAD extents. Returns one on a
/// match, zero otherwise. Names remain valid while their owning image is
/// loaded, like dlsym results; this does not grant execution authority.
///
/// # Safety
/// `output` must designate writable Dl_info storage.
#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub unsafe extern "C" fn dladdr(address: *const c_void, output: *mut DlInfo) -> c_int {
    let result = dlfcn::inspect(|images| {
        if output.is_null() {
            return Err(EFAULT);
        }
        for bytes in images {
            let image = Image::parse(bytes)?;
            for index in 0..image.count() {
                let entry = image.entry(index)?;
                if !entry.contains(address as u64) {
                    continue;
                }
                let symbol = entry.symbol(address as u64);
                let name = if entry.name.is_empty() {
                    executable_name::getexecname()
                } else {
                    entry.name.as_ptr().cast()
                };
                // No Rust padding or references are written to application memory.
                let fields = [
                    name as usize,
                    entry.base() as usize,
                    symbol.map(|(name, _)| name.as_ptr() as usize).unwrap_or(0),
                    symbol.map(|(_, address)| address as usize).unwrap_or(0),
                ];
                let mut encoded = [0u8; 32];
                for (slot, value) in encoded.chunks_exact_mut(8).zip(fields) {
                    slot.copy_from_slice(&value.to_ne_bytes());
                }
                user_copy::write(output.cast(), &encoded)?;
                return Ok(1);
            }
        }
        Ok(0)
    });
    result_with_errno(result, 0)
}

/// Supported common prefix of GNU dl_phdr_info. Callback `size` is 32; GNU
/// suffix members (loader counters and dynamic TLS) are not advertised.
#[repr(C)]
pub struct DlPhdrInfo {
    address: u64,
    name: *const c_char,
    headers: *const c_void,
    count: u16,
    padding: [u8; 6],
}

/// Visit a consistent snapshot of initial and late-loaded object headers.
/// Callback execution holds no loader mutex, allowing reentrant inspection
/// and loads. A nonzero callback result stops iteration and is returned.
/// Snapshot names/headers remain valid only for the duration of this call.
///
/// # Safety
/// `callback` must be a valid C function, and `data` valid for that callback.
#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub unsafe extern "C" fn dl_iterate_phdr(
    callback: Option<unsafe extern "C" fn(*mut DlPhdrInfo, usize, *mut c_void) -> c_int>,
    data: *mut c_void,
) -> c_int {
    let result = (|| {
        let callback = callback.ok_or(EINVAL)?;
        let length = dlfcn::inspect(|images| {
            images.iter().try_fold(0usize, |total, image| {
                total
                    .checked_add((image.len() + 7) & !7)
                    .filter(|n| *n <= wire::MAX_BYTES)
                    .ok_or(E2BIG)
            })
        })?;
        if initial().is_empty() {
            return Err(ENOTSUP);
        }
        io_resources::with(
            || startup_storage::Buffer::new(length),
            |snapshot| {
                let used = dlfcn::inspect(|images| {
                    let mut cursor = 0;
                    for image in images {
                        let end = cursor + image.len();
                        if end > snapshot.bytes().len() {
                            return Err(EAGAIN);
                        }
                        snapshot.bytes_mut()[cursor..end].copy_from_slice(image);
                        cursor = (end + 7) & !7;
                    }
                    Ok(cursor)
                })?;
                let mut cursor = 0;
                while cursor < used {
                    let length = u64::from_le_bytes(
                        snapshot.bytes()[cursor + 8..cursor + 16]
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    let image = Image::parse(&snapshot.bytes()[cursor..cursor + length])?;
                    for index in 0..image.count() {
                        let entry = image.entry(index)?;
                        let mut information = DlPhdrInfo {
                            address: entry.bias,
                            name: entry.name.as_ptr().cast(),
                            headers: entry.headers.as_ptr().cast(),
                            count: u16::try_from(entry.headers.len() / 56)
                                .map_err(|_| EOVERFLOW)?,
                            padding: [0; 6],
                        };
                        let code = unsafe {
                            callback(&mut information, core::mem::size_of::<DlPhdrInfo>(), data)
                        };
                        if code != 0 {
                            return Ok(code);
                        }
                    }
                    cursor = (cursor + length + 7) & !7;
                }
                Ok(0)
            },
        )
    })();
    result_with_errno(result, -1)
}
