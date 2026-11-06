//! Initial public C interface for authenticated, local, eagerly bound groups.
//! Unsupported namespace/TLS profiles fail explicitly; no loader success is
//! synthesized. Persistent owners never borrow the operation's Rust stack.
use super::*;
use mochios_posix_client::{
    elf_mapping::native::{Critical, Memory},
    image_preparation::{self as input, Backend},
};

const GROUPS: usize = 32;
const MEMBERS: usize = 64;
type Graph = input::resident::Library<library_source::Reader, Memory<Deferred>, MEMBERS>;
#[derive(Default)]
struct Library {
    graph: Graph,
    files: library_identity::Files,
}
impl Deref for Library {
    type Target = Graph;
    fn deref(&self) -> &Graph {
        &self.graph
    }
}
impl DerefMut for Library {
    fn deref_mut(&mut self) -> &mut Graph {
        &mut self.graph
    }
}
struct Deferred;
impl Critical for Deferred {
    fn run<T>(f: impl FnOnce() -> T) -> T {
        let _delivery = defer_native_delivery();
        f()
    }
}

pub(super) struct ErrorSlot {
    bytes: UnsafeCell<[u8; 192]>,
    pending: AtomicU32,
}
impl ErrorSlot {
    pub const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new([0; 192]),
            pending: AtomicU32::new(0),
        }
    }
    // Only the owning thread, with asynchronous native delivery deferred,
    // accesses the character buffer. Thread-slot recycling is exclusive.
    pub unsafe fn reset(&self) {
        self.pending.store(0, Ordering::Relaxed);
    }
    fn set(&self, message: &[u8]) {
        let _delivery = defer_native_delivery();
        let bytes = unsafe { &mut *self.bytes.get() };
        let n = message.len().min(bytes.len() - 1);
        bytes[..n].copy_from_slice(&message[..n]);
        bytes[n] = 0;
        self.pending.store(1, Ordering::Release);
    }
}
// Buffer access is confined to the registered owning thread (see above).
unsafe impl Sync for ErrorSlot {}

#[derive(Clone, Copy)]
struct Entry {
    pointer: usize,
    generation: usize,
    references: u32,
    file: (u64, u64),
    ready: bool,
    order: u64,
}
impl Entry {
    const EMPTY: Self = Self {
        pointer: 0,
        generation: 0,
        references: 0,
        file: (0, 0),
        ready: false,
        order: 0,
    };
}
static TABLE: RuntimeMutex<[Entry; GROUPS]> = RuntimeMutex::new([Entry::EMPTY; GROUPS]);
static OWNER: AtomicU64 = AtomicU64::new(0);
static EPOCH: AtomicU32 = AtomicU32::new(0);
static HAD_LOAD: AtomicU32 = AtomicU32::new(0);
static NEXT_ADDRESS: AtomicU64 = AtomicU64::new(0x8_0000_0000);

/// Registered in the thread's callback chain before acquiring the loader lease.
/// Abandoning C callbacks cannot strand its lock or discard a mapped owner.
#[derive(Default)]
struct Operation {
    active: bool,
    slot: Option<usize>,
    pointer: usize,
    closing: bool,
}
impl Operation {
    fn acquire(&mut self) -> Result<(), c_int> {
        let id = native_thread_id().map_err(|e| map_kernel_errno(e.raw()))?;
        loop {
            let epoch = EPOCH.load(Ordering::Acquire);
            {
                let _delivery = defer_native_delivery();
                match OWNER.compare_exchange(0, id, Ordering::Acquire, Ordering::Relaxed) {
                    Ok(_) => {
                        self.active = true;
                        return Ok(());
                    }
                    // In particular, do not deadlock when an initializer or a
                    // signal handler attempts to reenter this initial API.
                    Err(owner) if owner == id => return Err(EBUSY),
                    Err(_) => {}
                }
            }
            mochios_posix_client::synchronization::wait_u32(
                &EPOCH,
                epoch,
                syscall::ADDRESS_WAIT_INFINITE,
            )
            .map_err(|e| map_kernel_errno(e.raw()))?;
        }
    }
    fn reserve(&mut self) -> Result<usize, c_int> {
        HAD_LOAD.store(1, Ordering::Release);
        let mut table = TABLE.lock();
        let (index, entry) = table
            .iter_mut()
            .enumerate()
            .find(|(_, e)| e.pointer == 0 && e.references == 0 && e.generation < (usize::MAX >> 8))
            .ok_or(EMFILE)?;
        entry.generation += 1;
        entry.references = 1;
        self.slot = Some(index);
        Ok(index)
    }
    fn publish(&mut self, file: (u64, u64), order: u64) -> *mut c_void {
        let mut table = TABLE.lock();
        let slot = self.slot.take().unwrap();
        let entry = &mut table[slot];
        entry.pointer = self.pointer;
        entry.file = file;
        entry.ready = true;
        entry.order = order;
        self.pointer = 0;
        ((entry.generation << 8) | (slot + 1)) as *mut c_void
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        let _delivery = defer_native_delivery();
        if let Some(slot) = self.slot.take() {
            if self.pointer != 0 {
                // The operation lease excludes other graph access. An owner
                // with failed unmaps remains quarantined in the table.
                let library = unsafe { &mut *(self.pointer as *mut Library) };
                library.abandon();
                if library.retained() == 0 {
                    unsafe {
                        ptr::drop_in_place(self.pointer as *mut Library);
                        free(self.pointer as *mut c_void);
                    }
                    let mut table = TABLE.lock();
                    let generation = table[slot].generation;
                    table[slot] = Entry {
                        generation,
                        ..Entry::EMPTY
                    };
                } else {
                    let mut table = TABLE.lock();
                    table[slot].pointer = self.pointer;
                    table[slot].ready = false;
                    // Preserve a failed public close for an explicit retry.
                    // Unpublished opens remain quarantined without a handle.
                    table[slot].references = u32::from(self.closing);
                }
            } else {
                let mut table = TABLE.lock();
                table[slot].references = 0;
            }
        }
        if self.active {
            OWNER.store(0, Ordering::Release);
            EPOCH.fetch_add(1, Ordering::Release);
            native_mutex_wake_all(&EPOCH);
        }
    }
}

fn operation<T: Copy>(f: impl FnOnce(&mut Operation) -> Result<T, c_int>) -> Result<T, c_int> {
    io_resources::with(
        || Ok(Operation::default()),
        |operation| {
            operation.acquire()?;
            f(operation)
        },
    )
}
fn entry(handle: *mut c_void, allow_failed_close: bool) -> Result<(usize, Entry), c_int> {
    let raw = handle as usize;
    let index = (raw & 255)
        .checked_sub(1)
        .filter(|i| *i < GROUPS)
        .ok_or(EINVAL)?;
    let entry = TABLE.lock()[index];
    if entry.generation != raw >> 8
        || entry.references == 0
        || (!entry.ready && !allow_failed_close)
        || entry.pointer == 0
    {
        return Err(EINVAL);
    }
    Ok((index, entry))
}
fn invoke(address: u64) -> Result<(), syscall::SysError> {
    // Resident validates every callback against the captured executable LOADs.
    // The operation owner is already registered for nonlocal callback exits.
    unsafe { core::mem::transmute::<u64, unsafe extern "C" fn()>(address)() };
    Ok(())
}
fn library_error(error: input::resident::Error<syscall::SysError>) -> c_int {
    use input::resident::Error;
    match error {
        Error::Source(error) => error,
        Error::Elf(mochios_posix_client::pie::Error::Unsupported) => ENOTSUP,
        Error::Elf(_) => ENOEXEC,
        Error::Resident(error) => match error.operation {
            mochios_posix_client::pie::link_scope::resident::Operation::Memory(
                mochios_posix_client::elf_mapping::Error::Native(e)
                | mochios_posix_client::elf_mapping::Error::Cleanup { operation: e, .. },
            ) => mochios_posix_client::memory::map_errno(e.raw()),
            _ => ENOEXEC,
        },
    }
}
fn report<T>(result: Result<T, c_int>, failure: T) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            let text = match error {
                EACCES => {
                    b"dynamic loader: code authentication or capability ceiling denied".as_slice()
                }
                ENOENT => b"dynamic loader: library, dependency or symbol not found",
                ENOTSUP => b"dynamic loader: requested namespace or ELF profile is not supported",
                EBUSY => {
                    b"dynamic loader: reentrant load or shared group requires namespace support"
                }
                EFAULT => b"dynamic loader: invalid application string pointer",
                EINVAL => b"dynamic loader: invalid or closed handle, or invalid mode",
                ENOMEM | EMFILE => b"dynamic loader: resource limit exceeded",
                _ => b"dynamic loader: capture, relocation, mapping or lifecycle operation failed",
            };
            if let Some((_, control)) = current_thread_control() {
                control.loader_error.set(text);
            }
            set_errno(error);
            failure
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void {
    let result = operation(|operation| {
        if filename.is_null() {
            return Err(ENOTSUP);
        }
        // Linux-compatible values. LAZY is legally resolved eagerly. Global,
        // NOLOAD, NODELETE and DEEPBIND await shared/initial namespace support.
        if flags != 1 && flags != 2 {
            return Err(if flags & !3 != 0 { ENOTSUP } else { EINVAL });
        }
        let mut path = [0; posix_protocol::MAX_PATH_LEN];
        let n = user_copy::capture_text(filename, &mut path, ENAMETOOLONG)?;
        if n == 0 {
            return Err(ENOENT);
        }
        let identity = posix_client()
            .map_err(map_posix_client_error)?
            .session_info()
            .map(mochios_posix_client::process_image::Identity::from)
            .map_err(map_posix_client_error)?;
        // Environment strings use fault-safe capture; never borrow mutable
        // application environ storage across broker calls or callbacks.
        let mut search = [0; posix_protocol::MAX_PATH_LEN];
        let search_length = if identity.is_secure() {
            0
        } else {
            let value = unsafe { getenv(c"LD_LIBRARY_PATH".as_ptr()) };
            if value.is_null() {
                0
            } else {
                user_copy::capture_text(value, &mut search, ENAMETOOLONG)?
            }
        };
        let reader = library_source::Reader::default();
        operation.reserve()?;
        Deferred::run(|| {
            let pointer = unsafe { malloc(core::mem::size_of::<Library>()) }.cast::<Library>();
            if pointer.is_null() {
                return Err(ENOMEM);
            }
            unsafe {
                pointer.write(Library::default());
            }
            operation.pointer = pointer as usize;
            Ok(())
        })?;
        let library = unsafe { &mut *(operation.pointer as *mut Library) };
        let address = NEXT_ADDRESS.fetch_add(0x1_0000_0000, Ordering::Relaxed);
        if address >= 0x4000_0000_0000 {
            return Err(ENOMEM);
        }
        let variables = input::Environment {
            library_path: (search_length != 0).then_some(&search[..search_length]),
            ..Default::default()
        };
        library.open(&reader, &path[..n], variables, identity, address)?;
        library.files = reader.files.get();
        let file = reader.root.get().ok_or(EIO)?;
        if file == (0, 0) {
            return Err(ENOTSUP);
        }
        {
            // The operation lease pins all entries. Comparing captured code
            // can be expensive, so hold no table lock and defer no callbacks
            // while doing it.
            let entries = *TABLE.lock();
            for (index, old) in entries.iter().enumerate() {
                if !old.ready {
                    continue;
                }
                let prior = unsafe { &*(old.pointer as *const Library) };
                if old.file == file {
                    if prior.source() != library.source() {
                        return Err(EBUSY);
                    }
                    TABLE.lock()[index].references = old.references.checked_add(1).ok_or(EMFILE)?;
                    return Ok(((old.generation << 8) | (index + 1)) as *mut c_void);
                }
                if prior.files.intersects(&library.files) {
                    return Err(EBUSY);
                }
            }
        }
        let ceiling = address_space::snapshot()?.byte_ceiling();
        library
            .install(|| Memory::new(ceiling))
            .map_err(library_error)?;
        if let Err(error) = library.initialize(invoke) {
            let _ = library.close(invoke);
            return Err(library_error(error));
        }
        Ok(operation.publish(file, address))
    });
    report(result, ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void {
    let result = operation(|_| {
        if handle.is_null() || handle as usize == usize::MAX {
            return Err(ENOTSUP);
        }
        let (_, entry) = entry(handle, false)?;
        let mut name_bytes = [0; 1024];
        let n = user_copy::capture_text(name, &mut name_bytes, ENAMETOOLONG)?;
        let library = unsafe { &mut *(entry.pointer as *mut Library) };
        library
            .symbol(&name_bytes[..n])
            .map_err(library_error)?
            .map(|p| p as *mut c_void)
            .ok_or(ENOENT)
    });
    report(result, ptr::null_mut())
}

/// Normal process teardown closes late-loaded groups before the initial
/// executable scope. Live application references no longer pin code at exit.
pub(super) fn finalize() -> Result<(), c_int> {
    // Never acquire TABLE outside a callback-resource scope: a simultaneous
    // fork must not inherit a locked mutex owned by a vanished thread.
    if HAD_LOAD.load(Ordering::Acquire) == 0 {
        return Ok(());
    }
    operation(|operation| {
        loop {
            let next = TABLE
                .lock()
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.pointer != 0)
                .max_by_key(|(_, entry)| entry.order)
                .map(|(slot, entry)| (slot, *entry));
            let Some((slot, entry)) = next else {
                return Ok(());
            };
            Deferred::run(|| {
                TABLE.lock()[slot].ready = false;
                operation.slot = Some(slot);
                operation.pointer = entry.pointer;
            });
            let library = unsafe { &mut *(entry.pointer as *mut Library) };
            library.abandon();
            library.close(invoke).map_err(library_error)?;
            // Retire this owner without dropping the outer loader lease.
            Deferred::run(|| {
                unsafe {
                    ptr::drop_in_place(entry.pointer as *mut Library);
                    free(entry.pointer as *mut c_void);
                }
                let mut table = TABLE.lock();
                table[slot] = Entry {
                    generation: entry.generation,
                    ..Entry::EMPTY
                };
                operation.pointer = 0;
                operation.slot = None;
            });
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn dlclose(handle: *mut c_void) -> c_int {
    let result = operation(|operation| {
        let (slot, entry) = entry(handle, true)?;
        if entry.references > 1 {
            TABLE.lock()[slot].references -= 1;
            return Ok(0);
        }
        Deferred::run(|| {
            let mut table = TABLE.lock();
            table[slot].ready = false;
            operation.slot = Some(slot);
            operation.pointer = entry.pointer;
            operation.closing = true;
        });
        let library = unsafe { &mut *(entry.pointer as *mut Library) };
        library.close(invoke).map_err(library_error)?;
        Ok(0)
    });
    report(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn dlerror() -> *mut c_char {
    let _delivery = defer_native_delivery();
    let Some((_, control)) = current_thread_control() else {
        return ptr::null_mut();
    };
    if control.loader_error.pending.swap(0, Ordering::AcqRel) == 0 {
        return ptr::null_mut();
    }
    control.loader_error.bytes.get().cast::<c_char>()
}
