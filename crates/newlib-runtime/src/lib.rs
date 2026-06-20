#![no_std]

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use mochi_user_syscall as syscall;

const PAGE_SIZE: usize = 4096;
const MAX_FDS: usize = 64;
const PROT_READ_WRITE: u64 = 0x3;
const MAP_PRIVATE_ANON: u64 = 0x22;
const AT_FDCWD: i64 = -100;
const SEEK_CUR: c_int = 1;
const WNOHANG: c_int = 1;
const SPAWN_FAIL_EXIT_STATUS: c_int = 127;
const FD_STATE_ENV_PREFIX: &[u8] = b"MOCHIOS_FDSTATE=";
const MAX_FD_STATE_LEN: usize = 4096;
const MAX_ENV_POINTERS: usize = 128;
const MAX_SPAWN_FILE_ACTIONS: usize = 8;
const MAX_SPAWN_FILE_ACTION_ENTRIES: usize = 32;

const EPERM: c_int = 1;
const ENOENT: c_int = 2;
const ESRCH: c_int = 3;
const EINTR: c_int = 4;
const EIO: c_int = 5;
const EBADF: c_int = 9;
const EAGAIN: c_int = 11;
const ENOMEM: c_int = 12;
const EACCES: c_int = 13;
const EFAULT: c_int = 14;
const EEXIST: c_int = 17;
const ENOTDIR: c_int = 20;
const EISDIR: c_int = 21;
const EINVAL: c_int = 22;
const ESPIPE: c_int = 29;
const EPIPE: c_int = 32;
const ENOSYS: c_int = 38;

type InitFn = unsafe extern "C" fn();

#[repr(C)]
pub struct Tms {
    tms_utime: i64,
    tms_stime: i64,
    tms_cutime: i64,
    tms_cstime: i64,
}

#[repr(C)]
pub struct LockOpaque {
    _private: u8,
}

#[repr(C)]
pub struct PosixSpawnAttr {
    sa_flags: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PosixSpawnFileActions {
    fa_list: StailqHead<PosixSpawnFileActionsEntry>,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct StailqHead<T> {
    stqh_first: *mut T,
    stqh_last: *mut *mut T,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct StailqEntry<T> {
    stqe_next: *mut T,
}

#[repr(C)]
#[derive(Clone, Copy)]
union PosixSpawnFileActionData {
    open: PosixSpawnFileActionOpen,
    dup2: PosixSpawnFileActionDup2,
    dir: *mut c_char,
    dirfd: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PosixSpawnFileActionOpen {
    path: *mut c_char,
    oflag: c_int,
    mode: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PosixSpawnFileActionDup2 {
    newfildes: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PosixSpawnFileActionsEntry {
    fae_list: StailqEntry<PosixSpawnFileActionsEntry>,
    fae_action: c_int,
    fae_fildes: c_int,
    fae_data: PosixSpawnFileActionData,
}

#[derive(Clone, Copy)]
struct FileActionsSlot {
    in_use: bool,
    value: PosixSpawnFileActions,
}

impl FileActionsSlot {
    const fn new() -> Self {
        Self {
            in_use: false,
            value: PosixSpawnFileActions {
                fa_list: StailqHead {
                    stqh_first: ptr::null_mut(),
                    stqh_last: ptr::null_mut(),
                },
            },
        }
    }
}

#[derive(Clone, Copy)]
struct FileActionEntrySlot {
    in_use: bool,
    value: PosixSpawnFileActionsEntry,
}

impl FileActionEntrySlot {
    const fn new() -> Self {
        Self {
            in_use: false,
            value: PosixSpawnFileActionsEntry {
                fae_list: StailqEntry {
                    stqe_next: ptr::null_mut(),
                },
                fae_action: 0,
                fae_fildes: 0,
                fae_data: PosixSpawnFileActionData {
                    dirfd: 0,
                },
            },
        }
    }
}

const FAE_OPEN: c_int = 0;
const FAE_DUP2: c_int = 1;
const FAE_CLOSE: c_int = 2;
const FAE_CHDIR: c_int = 3;
const FAE_FCHDIR: c_int = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum FdKind {
    Unused = 0,
    Stdin = 1,
    Stdout = 2,
    Stderr = 3,
    File = 4,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct FdEntry {
    in_use: bool,
    lower_handle: u64,
    kind: FdKind,
    open_flags: c_int,
    position: u64,
    close_owned: bool,
}

impl FdEntry {
    const fn unused() -> Self {
        Self {
            in_use: false,
            lower_handle: 0,
            kind: FdKind::Unused,
            open_flags: 0,
            position: 0,
            close_owned: false,
        }
    }

    const fn stdio(fd: u64, kind: FdKind) -> Self {
        Self {
            in_use: true,
            lower_handle: fd,
            kind,
            open_flags: 0,
            position: 0,
            close_owned: false,
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct HeapState {
    initialized: bool,
    base: usize,
    current_break: usize,
    mapped_end: usize,
    maximum_end: usize,
    page_size: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelTimespec {
    sec: i64,
    nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KernelStat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    st_uid: u32,
    st_gid: u32,
    __pad0: u32,
    st_rdev: u64,
    st_size: i64,
    st_blksize: i64,
    st_blocks: i64,
    st_atim: KernelTimespec,
    st_mtim: KernelTimespec,
    st_ctim: KernelTimespec,
    __unused: [u8; 24],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NewlibTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NewlibStat {
    st_dev: u16,
    st_ino: u16,
    st_mode: u32,
    st_nlink: u16,
    st_uid: u16,
    st_gid: u16,
    st_rdev: u16,
    st_size: i64,
    st_atim: NewlibTimespec,
    st_mtim: NewlibTimespec,
    st_ctim: NewlibTimespec,
    st_blksize: i64,
    st_blocks: i64,
    st_spare4: [i64; 2],
}

impl HeapState {
    const fn new() -> Self {
        Self {
            initialized: false,
            base: 0,
            current_break: 0,
            mapped_end: 0,
            maximum_end: 0,
            page_size: PAGE_SIZE,
        }
    }
}

#[repr(C)]
struct RuntimeState {
    initialized: bool,
    argv: *mut *mut c_char,
    envp: *mut *mut c_char,
    fds: [FdEntry; MAX_FDS],
    heap: HeapState,
}

impl RuntimeState {
    const fn new() -> Self {
        Self {
            initialized: false,
            argv: ptr::null_mut(),
            envp: ptr::null_mut(),
            fds: [FdEntry::unused(); MAX_FDS],
            heap: HeapState::new(),
        }
    }
}

struct SingleThreadCell<T> {
    inner: UnsafeCell<T>,
}

impl<T> SingleThreadCell<T> {
    const fn new(value: T) -> Self {
        Self {
            inner: UnsafeCell::new(value),
        }
    }

    unsafe fn get(&self) -> *mut T {
        self.inner.get()
    }
}

// Safety: the runtime is intentionally single-threaded for this bootstrap port.
unsafe impl<T> Sync for SingleThreadCell<T> {}

static STATE: SingleThreadCell<RuntimeState> = SingleThreadCell::new(RuntimeState::new());
static DUMMY_LOCK: LockOpaque = LockOpaque { _private: 0 };
static FILE_ACTIONS_POOL: SingleThreadCell<[FileActionsSlot; MAX_SPAWN_FILE_ACTIONS]> =
    SingleThreadCell::new([FileActionsSlot::new(); MAX_SPAWN_FILE_ACTIONS]);
static FILE_ACTION_ENTRIES_POOL: SingleThreadCell<
    [FileActionEntrySlot; MAX_SPAWN_FILE_ACTION_ENTRIES],
> = SingleThreadCell::new([FileActionEntrySlot::new(); MAX_SPAWN_FILE_ACTION_ENTRIES]);

#[unsafe(no_mangle)]
pub static mut errno: c_int = 0;

#[unsafe(no_mangle)]
pub static mut environ: *mut *mut c_char = ptr::null_mut();

#[unsafe(no_mangle)]
pub static mut __env: *mut *mut c_char = ptr::null_mut();

unsafe extern "C" {
    static __preinit_array_start: InitFn;
    static __preinit_array_end: InitFn;
    static __init_array_start: InitFn;
    static __init_array_end: InitFn;
    static __fini_array_start: InitFn;
    static __fini_array_end: InitFn;
    static mut _impure_ptr: *mut c_void;

    fn main(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) -> c_int;
    fn exit(code: c_int) -> !;
    fn atexit(func: extern "C" fn()) -> c_int;
    fn __sinit(reent: *mut c_void);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    process_exit(127)
}

#[derive(Clone, Copy)]
#[repr(C)]
struct StackView {
    argc: usize,
    argv: *mut *mut c_char,
    envp: *mut *mut c_char,
    stack_top: usize,
}

fn align_up(value: usize, align: usize) -> Option<usize> {
    let mask = align.checked_sub(1)?;
    value.checked_add(mask).map(|next| next & !mask)
}

fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

unsafe fn state_mut() -> &'static mut RuntimeState {
    // Safety: all accesses are serialized by the single-thread bootstrap model.
    unsafe { &mut *STATE.get() }
}

fn set_errno(value: c_int) {
    unsafe {
        errno = value;
    }
}

fn truncate_u16(value: u64) -> u16 {
    core::cmp::min(value, u16::MAX as u64) as u16
}

fn translate_stat(kernel: &KernelStat) -> NewlibStat {
    NewlibStat {
        st_dev: truncate_u16(kernel.st_dev),
        st_ino: truncate_u16(kernel.st_ino),
        st_mode: kernel.st_mode,
        st_nlink: truncate_u16(kernel.st_nlink),
        st_uid: truncate_u16(kernel.st_uid as u64),
        st_gid: truncate_u16(kernel.st_gid as u64),
        st_rdev: truncate_u16(kernel.st_rdev),
        st_size: kernel.st_size,
        st_atim: NewlibTimespec {
            tv_sec: kernel.st_atim.sec,
            tv_nsec: kernel.st_atim.nsec,
        },
        st_mtim: NewlibTimespec {
            tv_sec: kernel.st_mtim.sec,
            tv_nsec: kernel.st_mtim.nsec,
        },
        st_ctim: NewlibTimespec {
            tv_sec: kernel.st_ctim.sec,
            tv_nsec: kernel.st_ctim.nsec,
        },
        st_blksize: kernel.st_blksize,
        st_blocks: kernel.st_blocks,
        st_spare4: [0; 2],
    }
}

fn map_kernel_errno(raw: i64) -> c_int {
    let code = if raw < 0 {
        (-raw) as c_int
    } else {
        raw as c_int
    };
    match code {
        ENOENT => ENOENT,
        EACCES => EACCES,
        EINVAL => EINVAL,
        EBADF => EBADF,
        EAGAIN => EAGAIN,
        EEXIST => EEXIST,
        ENOTDIR => ENOTDIR,
        EISDIR => EISDIR,
        ENOMEM => ENOMEM,
        ENOSYS => ENOSYS,
        EINTR => EINTR,
        EPIPE => EPIPE,
        EPERM => EPERM,
        ESRCH => ESRCH,
        EIO => EIO,
        EFAULT => EFAULT,
        _ if code > 0 => code,
        _ => EIO,
    }
}

fn syscall_errno(result: syscall::RawSyscallResult) -> Result<u64, c_int> {
    let raw = result.raw() as i64;
    if raw < 0 {
        Err(map_kernel_errno(raw))
    } else {
        Ok(result.raw())
    }
}

fn result_with_errno<T>(result: Result<T, c_int>, error_value: T) -> T {
    match result {
        Ok(value) => value,
        Err(errno_value) => {
            set_errno(errno_value);
            error_value
        }
    }
}

unsafe fn parse_stack(sp: *const usize) -> StackView {
    let argc = unsafe { sp.read() };
    let argv = unsafe { sp.add(1) as *mut *mut c_char };
    let mut cursor = argv;
    for _ in 0..argc {
        cursor = unsafe { cursor.add(1) };
    }
    cursor = unsafe { cursor.add(1) };
    let envp = cursor;
    while !unsafe { cursor.read() }.is_null() {
        cursor = unsafe { cursor.add(1) };
    }
    StackView {
        argc,
        argv,
        envp,
        stack_top: sp as usize,
    }
}

unsafe fn call_init_array(start: *const InitFn, end: *const InitFn) {
    let mut current = start;
    while current < end {
        let init = unsafe { current.read() };
        unsafe { init() };
        current = unsafe { current.add(1) };
    }
}

unsafe fn c_strlen(mut ptr_value: *const c_char) -> usize {
    let mut len = 0usize;
    while unsafe { ptr_value.read() } != 0 {
        len += 1;
        ptr_value = unsafe { ptr_value.add(1) };
    }
    len
}

unsafe fn c_bytes<'a>(ptr_value: *const c_char) -> &'a [u8] {
    let len = unsafe { c_strlen(ptr_value) };
    // Safety: callers only pass valid C strings from the current process image.
    unsafe { core::slice::from_raw_parts(ptr_value.cast::<u8>(), len) }
}

fn push_decimal(mut value: usize, out: &mut [u8], length: &mut usize) -> Result<(), c_int> {
    let mut digits = [0u8; 20];
    let mut index = digits.len();
    if value == 0 {
        if *length >= out.len() {
            return Err(ENOMEM);
        }
        out[*length] = b'0';
        *length += 1;
        return Ok(());
    }
    while value != 0 {
        index -= 1;
        digits[index] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    let needed = digits.len() - index;
    if *length + needed > out.len() {
        return Err(ENOMEM);
    }
    out[*length..*length + needed].copy_from_slice(&digits[index..]);
    *length += needed;
    Ok(())
}

fn parse_decimal(mut bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0usize;
    while let Some((&head, tail)) = bytes.split_first() {
        if !head.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((head - b'0') as usize)?;
        bytes = tail;
    }
    Some(value)
}

fn find_fd_state_env(envp: *mut *mut c_char) -> Option<&'static [u8]> {
    if envp.is_null() {
        return None;
    }
    let mut cursor = envp;
    loop {
        // Safety: envp is the kernel-provided environment vector for the current process.
        let entry = unsafe { cursor.read() };
        if entry.is_null() {
            return None;
        }
        let bytes = unsafe { c_bytes(entry.cast_const()) };
        if let Some(rest) = bytes.strip_prefix(FD_STATE_ENV_PREFIX) {
            return Some(rest);
        }
        // Safety: cursor is advanced within the NUL-terminated envp vector.
        cursor = unsafe { cursor.add(1) };
    }
}

fn restore_fd_state_from_env(envp: *mut *mut c_char, fds: &mut [FdEntry; MAX_FDS]) -> bool {
    let Some(raw) = find_fd_state_env(envp) else {
        return false;
    };
    *fds = [FdEntry::unused(); MAX_FDS];
    for record in raw.split(|byte| *byte == b';') {
        if record.is_empty() {
            continue;
        }
        let mut fields = record.split(|byte| *byte == b',');
        let Some(fd) = fields.next().and_then(parse_decimal) else {
            return false;
        };
        let Some(kind_code) = fields.next().and_then(parse_decimal) else {
            return false;
        };
        let Some(lower_handle) = fields.next().and_then(parse_decimal) else {
            return false;
        };
        let Some(open_flags) = fields.next().and_then(parse_decimal) else {
            return false;
        };
        let Some(position) = fields.next().and_then(parse_decimal) else {
            return false;
        };
        let Some(close_owned) = fields.next().and_then(parse_decimal) else {
            return false;
        };
        if fd >= MAX_FDS {
            return false;
        }
        let kind = match kind_code {
            1 => FdKind::Stdin,
            2 => FdKind::Stdout,
            3 => FdKind::Stderr,
            4 => FdKind::File,
            _ => return false,
        };
        fds[fd] = FdEntry {
            in_use: true,
            lower_handle: lower_handle as u64,
            kind,
            open_flags: open_flags as c_int,
            position: position as u64,
            close_owned: close_owned != 0,
        };
    }
    true
}

fn push_byte(out: &mut [u8], length: &mut usize, value: u8) -> Result<(), c_int> {
    if *length >= out.len() {
        return Err(ENOMEM);
    }
    out[*length] = value;
    *length += 1;
    Ok(())
}

fn serialize_fd_state(
    fds: &[FdEntry; MAX_FDS],
    encoded: &mut [u8; MAX_FD_STATE_LEN],
) -> Result<usize, c_int> {
    let mut length = 0usize;
    if FD_STATE_ENV_PREFIX.len() > encoded.len() {
        return Err(ENOMEM);
    }
    encoded[..FD_STATE_ENV_PREFIX.len()].copy_from_slice(FD_STATE_ENV_PREFIX);
    length += FD_STATE_ENV_PREFIX.len();
    for (fd, entry) in fds.iter().enumerate() {
        if !entry.in_use {
            continue;
        }
        let kind_code = match entry.kind {
            FdKind::Unused => continue,
            FdKind::Stdin => 1usize,
            FdKind::Stdout => 2usize,
            FdKind::Stderr => 3usize,
            FdKind::File => 4usize,
        };
        push_decimal(fd, encoded, &mut length)?;
        push_byte(encoded, &mut length, b',')?;
        push_decimal(kind_code, encoded, &mut length)?;
        push_byte(encoded, &mut length, b',')?;
        push_decimal(entry.lower_handle as usize, encoded, &mut length)?;
        push_byte(encoded, &mut length, b',')?;
        push_decimal(entry.open_flags.max(0) as usize, encoded, &mut length)?;
        push_byte(encoded, &mut length, b',')?;
        push_decimal(entry.position as usize, encoded, &mut length)?;
        push_byte(encoded, &mut length, b',')?;
        push_decimal(entry.close_owned as usize, encoded, &mut length)?;
        push_byte(encoded, &mut length, b';')?;
    }
    push_byte(encoded, &mut length, 0)?;
    Ok(length)
}

extern "C" fn run_fini_array() {
    unsafe {
        call_init_array(
            ptr::addr_of!(__fini_array_start),
            ptr::addr_of!(__fini_array_end),
        );
    }
}

unsafe fn initialize_runtime(stack: StackView) {
    let state = unsafe { state_mut() };
    if state.initialized {
        return;
    }

    state.initialized = true;
    state.argv = stack.argv;
    state.envp = stack.envp;
    if !restore_fd_state_from_env(stack.envp, &mut state.fds) {
        state.fds[0] = FdEntry::stdio(0, FdKind::Stdin);
        state.fds[1] = FdEntry::stdio(1, FdKind::Stdout);
        state.fds[2] = FdEntry::stdio(2, FdKind::Stderr);
    }

    let stack_limit = align_down(stack.stack_top, PAGE_SIZE).saturating_sub(PAGE_SIZE);
    state.heap = HeapState {
        initialized: true,
        // Kernel owns the initial user heap placement. Delay heap bootstrap
        // until _sbrk() so userland does not guess a virtual address.
        base: 0,
        current_break: 0,
        mapped_end: 0,
        maximum_end: stack_limit,
        page_size: PAGE_SIZE,
    };

    unsafe {
        environ = stack.envp;
        __env = stack.envp;
    }

    let _ = unsafe { atexit(run_fini_array) };
}

unsafe fn init_file_actions_list(value: *mut PosixSpawnFileActions) {
    // Safety: caller passes a pointer to a live pool slot owned by this runtime.
    unsafe {
        (*value).fa_list.stqh_first = ptr::null_mut();
        (*value).fa_list.stqh_last = ptr::addr_of_mut!((*value).fa_list.stqh_first);
    }
}

unsafe fn allocate_file_actions_object() -> Result<*mut PosixSpawnFileActions, c_int> {
    // Safety: bootstrap runtime is single-threaded, so pool mutation is serialized.
    let pool = unsafe { &mut *FILE_ACTIONS_POOL.get() };
    for slot in pool.iter_mut() {
        if !slot.in_use {
            slot.in_use = true;
            let value = ptr::addr_of_mut!(slot.value);
            unsafe { init_file_actions_list(value) };
            return Ok(value);
        }
    }
    Err(ENOMEM)
}

unsafe fn release_file_actions_object(target: *mut PosixSpawnFileActions) {
    // Safety: bootstrap runtime is single-threaded, so pool mutation is serialized.
    let pool = unsafe { &mut *FILE_ACTIONS_POOL.get() };
    for slot in pool.iter_mut() {
        let slot_ptr = ptr::addr_of_mut!(slot.value);
        if slot_ptr == target {
            slot.in_use = false;
            unsafe { init_file_actions_list(slot_ptr) };
            return;
        }
    }
}

unsafe fn allocate_file_action_entry() -> Result<*mut PosixSpawnFileActionsEntry, c_int> {
    // Safety: bootstrap runtime is single-threaded, so pool mutation is serialized.
    let pool = unsafe { &mut *FILE_ACTION_ENTRIES_POOL.get() };
    for slot in pool.iter_mut() {
        if !slot.in_use {
            slot.in_use = true;
            slot.value.fae_list.stqe_next = ptr::null_mut();
            return Ok(ptr::addr_of_mut!(slot.value));
        }
    }
    Err(ENOMEM)
}

unsafe fn release_file_action_entry(target: *mut PosixSpawnFileActionsEntry) {
    // Safety: bootstrap runtime is single-threaded, so pool mutation is serialized.
    let pool = unsafe { &mut *FILE_ACTION_ENTRIES_POOL.get() };
    for slot in pool.iter_mut() {
        let slot_ptr = ptr::addr_of_mut!(slot.value);
        if slot_ptr == target {
            slot.in_use = false;
            slot.value.fae_list.stqe_next = ptr::null_mut();
            slot.value.fae_action = 0;
            slot.value.fae_fildes = 0;
            slot.value.fae_data.dirfd = 0;
            return;
        }
    }
}

unsafe fn append_file_action(
    actions: *mut PosixSpawnFileActions,
    entry: *mut PosixSpawnFileActionsEntry,
) {
    // Safety: caller provides pointers to live pool slots exclusively owned here.
    unsafe {
        (*entry).fae_list.stqe_next = ptr::null_mut();
        *(*actions).fa_list.stqh_last = entry;
        (*actions).fa_list.stqh_last = ptr::addr_of_mut!((*entry).fae_list.stqe_next);
    }
}

fn clone_current_fd_table() -> [FdEntry; MAX_FDS] {
    // Safety: bootstrap runtime is single-threaded, so copying the table is race-free.
    unsafe { state_mut().fds }
}

fn clear_fd_entry(fds: &mut [FdEntry; MAX_FDS], fd: c_int) {
    if fd >= 0 && (fd as usize) < MAX_FDS {
        fds[fd as usize] = FdEntry::unused();
    }
}

fn rewrite_fd_entry(
    fds: &mut [FdEntry; MAX_FDS],
    old_fd: c_int,
    new_fd: c_int,
) -> Result<(), c_int> {
    if old_fd < 0 || new_fd < 0 || old_fd as usize >= MAX_FDS || new_fd as usize >= MAX_FDS {
        return Err(EBADF);
    }
    let old_entry = fds[old_fd as usize];
    if !old_entry.in_use {
        return Err(EBADF);
    }
    if old_fd == new_fd {
        return Ok(());
    }
    let new_index = new_fd as usize;
    let mut new_entry = old_entry;
    // posix_spawn の child-side file actions は fork 後・execve 前の一時 FD table を
    // 組み替えるだけでよい。kernel の dup2 syscall は process-local FD 番号を要求するため、
    // runtime 内部の lower_handle を渡してはいけない。
    new_entry.close_owned = old_entry.close_owned;
    fds[new_index] = new_entry;
    Ok(())
}

fn apply_spawn_file_actions(
    fds: &mut [FdEntry; MAX_FDS],
    actions: *const *mut PosixSpawnFileActions,
) -> Result<(), c_int> {
    if actions.is_null() {
        return Ok(());
    }
    // Safety: file_actions is a pointer to the caller's posix_spawn_file_actions_t handle.
    let actions = unsafe { *actions };
    if actions.is_null() {
        return Ok(());
    }
    // Safety: actions points to a live queue object allocated by this runtime.
    let mut current = unsafe { (*actions).fa_list.stqh_first };
    while !current.is_null() {
        // Safety: current walks the STAILQ built by newlib's posix_spawn_file_actions APIs.
        let entry = unsafe { &*current };
        match entry.fae_action {
            FAE_CLOSE => clear_fd_entry(fds, entry.fae_fildes),
            FAE_DUP2 => {
                // Safety: the active union field is determined by fae_action.
                let new_fd = unsafe { entry.fae_data.dup2.newfildes };
                rewrite_fd_entry(fds, entry.fae_fildes, new_fd)?;
            }
            FAE_OPEN | FAE_CHDIR | FAE_FCHDIR => return Err(ENOSYS),
            _ => return Err(EINVAL),
        }
        // Safety: advance within the same STAILQ.
        current = entry.fae_list.stqe_next;
    }
    Ok(())
}

fn collect_envp_with_fd_state(
    envp: *const *const c_char,
    fd_state: *const c_char,
    out: &mut [*const c_char; MAX_ENV_POINTERS],
) -> Result<(), c_int> {
    let source_envp = if envp.is_null() {
        // Safety: environ is initialized from the process startup stack before main().
        unsafe { environ as *const *const c_char }
    } else {
        envp
    };
    let mut length = 0usize;
    if !source_envp.is_null() {
        let mut cursor = source_envp;
        loop {
            // Safety: source_envp is a NUL-terminated environment pointer array.
            let entry = unsafe { cursor.read() };
            if entry.is_null() {
                break;
            }
            let keep = unsafe { c_bytes(entry) }
                .strip_prefix(FD_STATE_ENV_PREFIX)
                .is_none();
            if keep {
                if length + 2 > out.len() {
                    return Err(ENOMEM);
                }
                out[length] = entry;
                length += 1;
            }
            // Safety: cursor advances within the envp array.
            cursor = unsafe { cursor.add(1) };
        }
    }
    if length + 2 > out.len() {
        return Err(ENOMEM);
    }
    out[length] = fd_state;
    out[length + 1] = ptr::null();
    Ok(())
}

fn execve_raw(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> Result<(), c_int> {
    let _ = syscall_errno(syscall::raw_syscall3(
        syscall::SyscallNumber::Execve,
        path as u64,
        argv as u64,
        envp as u64,
    ))?;
    Ok(())
}

#[inline(never)]
fn process_spawn_raw() -> u64 {
    syscall::raw_syscall2(syscall::SyscallNumber::ProcessSpawn, 0, 0).raw()
}

fn unsupported_spawn_attr(attr: *const *mut PosixSpawnAttr) -> Result<(), c_int> {
    if attr.is_null() {
        return Ok(());
    }
    // Safety: attr points to the caller's posix_spawnattr_t handle.
    let attr = unsafe { *attr };
    if attr.is_null() {
        return Ok(());
    }
    // Safety: attr points to the caller's posix_spawnattr object.
    let flags = unsafe { (*attr).sa_flags };
    if flags != 0 {
        return Err(ENOSYS);
    }
    Ok(())
}

fn with_fd_entry(fd: c_int) -> Result<FdEntry, c_int> {
    if fd < 0 || fd as usize >= MAX_FDS {
        return Err(EBADF);
    }
    let entry = unsafe { state_mut().fds[fd as usize] };
    if !entry.in_use {
        return Err(EBADF);
    }
    Ok(entry)
}

fn allocate_fd(lower_handle: u64, flags: c_int) -> Result<c_int, c_int> {
    let state = unsafe { state_mut() };
    for index in 3..MAX_FDS {
        if !state.fds[index].in_use {
            state.fds[index] = FdEntry {
                in_use: true,
                lower_handle,
                kind: FdKind::File,
                open_flags: flags,
                position: 0,
                close_owned: true,
            };
            return Ok(index as c_int);
        }
    }
    Err(ENOMEM)
}

fn store_position(fd: c_int, position: u64) {
    unsafe {
        let state = state_mut();
        if fd >= 0 && (fd as usize) < MAX_FDS && state.fds[fd as usize].in_use {
            state.fds[fd as usize].position = position;
        }
    }
}

fn advance_position(fd: c_int, amount: u64) {
    unsafe {
        let state = state_mut();
        if fd >= 0 && (fd as usize) < MAX_FDS && state.fds[fd as usize].in_use {
            state.fds[fd as usize].position =
                state.fds[fd as usize].position.saturating_add(amount);
        }
    }
}

fn syscall_write(entry: FdEntry, buffer: *const c_void, length: usize) -> Result<isize, c_int> {
    let number = match entry.kind {
        FdKind::Stdout | FdKind::Stderr => syscall::SyscallNumber::Write,
        FdKind::File => syscall::SyscallNumber::FileWrite,
        _ => return Err(EBADF),
    };
    let written = syscall_errno(syscall::raw_syscall3(
        number,
        entry.lower_handle,
        buffer as u64,
        length as u64,
    ))?;
    Ok(written as isize)
}

fn syscall_read(
    fd: c_int,
    entry: FdEntry,
    buffer: *mut c_void,
    length: usize,
) -> Result<isize, c_int> {
    let number = match entry.kind {
        FdKind::Stdin => syscall::SyscallNumber::Read,
        FdKind::File => syscall::SyscallNumber::FileRead,
        _ => return Err(EBADF),
    };
    let read = syscall_errno(syscall::raw_syscall3(
        number,
        entry.lower_handle,
        buffer as u64,
        length as u64,
    ))?;
    if matches!(entry.kind, FdKind::File) {
        advance_position(fd, read);
    }
    Ok(read as isize)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start_c(initial_sp: *const usize) -> ! {
    let stack = unsafe { parse_stack(initial_sp) };
    unsafe { initialize_runtime(stack) };
    unsafe { __sinit(_impure_ptr) };
    unsafe {
        call_init_array(
            ptr::addr_of!(__preinit_array_start),
            ptr::addr_of!(__preinit_array_end),
        )
    };
    unsafe {
        call_init_array(
            ptr::addr_of!(__init_array_start),
            ptr::addr_of!(__init_array_end),
        )
    };
    let code = unsafe { main(stack.argc as c_int, stack.argv, stack.envp) };
    unsafe { exit(code) }
}

#[unsafe(no_mangle)]
pub extern "C" fn __errno() -> *mut c_int {
    core::ptr::addr_of_mut!(errno)
}

#[unsafe(no_mangle)]
pub extern "C" fn _exit(status: c_int) -> ! {
    process_exit(status)
}

fn process_exit(code: c_int) -> ! {
    let _ = syscall::raw_syscall1(syscall::SyscallNumber::ProcessExit, code as u64);
    loop {
        core::hint::spin_loop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _write(fd: c_int, buffer: *const c_void, length: usize) -> isize {
    if length != 0 && buffer.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = (|| {
        let entry = with_fd_entry(fd)?;
        let written = syscall_write(entry, buffer, length)?;
        advance_position(fd, written as u64);
        Ok(written)
    })();
    result_with_errno(result, -1)
}

// This newlib configuration omits libc/syscalls/sys*.c connectors, and some
// reentrant wrappers still resolve through the plain POSIX spellings.
#[unsafe(no_mangle)]
pub extern "C" fn write(fd: c_int, buffer: *const c_void, length: usize) -> isize {
    _write(fd, buffer, length)
}

#[unsafe(no_mangle)]
pub extern "C" fn _read(fd: c_int, buffer: *mut c_void, length: usize) -> isize {
    if length != 0 && buffer.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = (|| {
        let entry = with_fd_entry(fd)?;
        syscall_read(fd, entry, buffer, length)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn read(fd: c_int, buffer: *mut c_void, length: usize) -> isize {
    _read(fd, buffer, length)
}

#[unsafe(no_mangle)]
pub extern "C" fn _open(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = (|| {
        let lower = syscall_errno(syscall::raw_syscall4(
            syscall::SyscallNumber::FileOpenAt,
            AT_FDCWD as u64,
            path as u64,
            flags as u64,
            mode as u64,
        ))?;
        let fd = allocate_fd(lower, flags)?;
        let offset = syscall_errno(syscall::raw_syscall3(
            syscall::SyscallNumber::FileSeek,
            lower,
            0,
            SEEK_CUR as u64,
        ))
        .unwrap_or(0);
        store_position(fd, offset);
        Ok(fd)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn open(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
    _open(path, flags, mode)
}

#[unsafe(no_mangle)]
pub extern "C" fn _close(fd: c_int) -> c_int {
    let result = (|| {
        let entry = with_fd_entry(fd)?;
        if entry.close_owned {
            let _ = syscall_errno(syscall::raw_syscall1(
                syscall::SyscallNumber::FileClose,
                entry.lower_handle,
            ))?;
        }
        unsafe {
            state_mut().fds[fd as usize] = FdEntry::unused();
        }
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn close(fd: c_int) -> c_int {
    _close(fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn _lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    let result = (|| {
        let entry = with_fd_entry(fd)?;
        if entry.kind != FdKind::File {
            return Err(ESPIPE);
        }
        let next = syscall_errno(syscall::raw_syscall3(
            syscall::SyscallNumber::FileSeek,
            entry.lower_handle,
            offset as u64,
            whence as u64,
        ))?;
        store_position(fd, next);
        Ok(next as i64)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    _lseek(fd, offset, whence)
}

#[unsafe(no_mangle)]
pub extern "C" fn _fstat(fd: c_int, stat_buf: *mut c_void) -> c_int {
    if stat_buf.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = (|| {
        let entry = with_fd_entry(fd)?;
        let mut kernel_stat = KernelStat {
            st_dev: 0,
            st_ino: 0,
            st_nlink: 0,
            st_mode: 0,
            st_uid: 0,
            st_gid: 0,
            __pad0: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 0,
            st_blocks: 0,
            st_atim: KernelTimespec { sec: 0, nsec: 0 },
            st_mtim: KernelTimespec { sec: 0, nsec: 0 },
            st_ctim: KernelTimespec { sec: 0, nsec: 0 },
            __unused: [0; 24],
        };
        let _ = syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::FileFstat,
            entry.lower_handle,
            (&mut kernel_stat as *mut KernelStat).cast::<c_void>() as u64,
        ))?;
        let translated = translate_stat(&kernel_stat);
        unsafe { ptr::write(stat_buf.cast::<NewlibStat>(), translated) };
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn fstat(fd: c_int, stat_buf: *mut c_void) -> c_int {
    _fstat(fd, stat_buf)
}

#[unsafe(no_mangle)]
pub extern "C" fn _stat(path: *const c_char, stat_buf: *mut c_void) -> c_int {
    if path.is_null() || stat_buf.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = (|| {
        let mut kernel_stat = KernelStat {
            st_dev: 0,
            st_ino: 0,
            st_nlink: 0,
            st_mode: 0,
            st_uid: 0,
            st_gid: 0,
            __pad0: 0,
            st_rdev: 0,
            st_size: 0,
            st_blksize: 0,
            st_blocks: 0,
            st_atim: KernelTimespec { sec: 0, nsec: 0 },
            st_mtim: KernelTimespec { sec: 0, nsec: 0 },
            st_ctim: KernelTimespec { sec: 0, nsec: 0 },
            __unused: [0; 24],
        };
        let _ = syscall_errno(syscall::raw_syscall4(
            syscall::SyscallNumber::FileStatAt,
            AT_FDCWD as u64,
            path as u64,
            (&mut kernel_stat as *mut KernelStat).cast::<c_void>() as u64,
            0,
        ))?;
        let translated = translate_stat(&kernel_stat);
        unsafe { ptr::write(stat_buf.cast::<NewlibStat>(), translated) };
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn stat(path: *const c_char, stat_buf: *mut c_void) -> c_int {
    _stat(path, stat_buf)
}

#[unsafe(no_mangle)]
pub extern "C" fn _isatty(fd: c_int) -> c_int {
    let result = (|| {
        let entry = with_fd_entry(fd)?;
        Ok(
            if matches!(entry.kind, FdKind::Stdin | FdKind::Stdout | FdKind::Stderr) {
                1
            } else {
                0
            },
        )
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn isatty(fd: c_int) -> c_int {
    _isatty(fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn _sbrk(increment: isize) -> *mut c_void {
    let result = (|| {
        let state = unsafe { state_mut() };
        let heap = &mut state.heap;
        if !heap.initialized {
            return Err(ENOMEM);
        }
        if heap.base == 0 {
            if increment < 0 {
                return Err(EINVAL);
            }
            let mapped = syscall_errno(syscall::raw_syscall5(
                syscall::SyscallNumber::MemoryMap,
                0,
                heap.page_size as u64,
                PROT_READ_WRITE,
                MAP_PRIVATE_ANON,
                0,
            ))? as usize;
            let mapped_end = mapped.checked_add(heap.page_size).ok_or(ENOMEM)?;
            if mapped_end > heap.maximum_end {
                return Err(ENOMEM);
            }
            heap.base = mapped;
            heap.current_break = mapped;
            heap.mapped_end = mapped_end;
        }
        let old_break = heap.current_break;
        let new_break = if increment >= 0 {
            old_break.checked_add(increment as usize).ok_or(ENOMEM)?
        } else {
            old_break
                .checked_sub(increment.unsigned_abs())
                .ok_or(EINVAL)?
        };
        if new_break < heap.base {
            return Err(EINVAL);
        }
        if new_break > heap.maximum_end {
            return Err(ENOMEM);
        }
        if new_break > heap.mapped_end {
            let target_end = align_up(new_break, heap.page_size).ok_or(ENOMEM)?;
            let map_len = target_end.checked_sub(heap.mapped_end).ok_or(ENOMEM)?;
            if map_len != 0 {
                let mapped = syscall_errno(syscall::raw_syscall5(
                    syscall::SyscallNumber::MemoryMap,
                    heap.mapped_end as u64,
                    map_len as u64,
                    PROT_READ_WRITE,
                    MAP_PRIVATE_ANON,
                    0,
                ))?;
                if mapped as usize != heap.mapped_end {
                    return Err(ENOMEM);
                }
                heap.mapped_end = target_end;
            }
        }
        heap.current_break = new_break;
        Ok(old_break as *mut c_void)
    })();
    result_with_errno(result, (-1isize) as *mut c_void)
}

#[unsafe(no_mangle)]
pub extern "C" fn sbrk(increment: isize) -> *mut c_void {
    _sbrk(increment)
}

#[unsafe(no_mangle)]
pub extern "C" fn _getpid() -> c_int {
    set_errno(ENOSYS);
    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn getpid() -> c_int {
    _getpid()
}

#[unsafe(no_mangle)]
pub extern "C" fn _kill(_pid: c_int, _sig: c_int) -> c_int {
    set_errno(ENOSYS);
    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn kill(pid: c_int, sig: c_int) -> c_int {
    _kill(pid, sig)
}

#[unsafe(no_mangle)]
pub extern "C" fn _times(buf: *mut Tms) -> i64 {
    if !buf.is_null() {
        unsafe {
            *buf = Tms {
                tms_utime: 0,
                tms_stime: 0,
                tms_cutime: 0,
                tms_cstime: 0,
            };
        }
    }
    let result = syscall_errno(syscall::raw_syscall0(syscall::SyscallNumber::TimeNow))
        .map(|ticks| ticks as i64);
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn times(buf: *mut Tms) -> i64 {
    _times(buf)
}

#[unsafe(no_mangle)]
pub extern "C" fn _unlink(path: *const c_char) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = (|| {
        let _ = syscall_errno(syscall::raw_syscall1(
            syscall::SyscallNumber::FileRemove,
            path as u64,
        ))?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn unlink(path: *const c_char) -> c_int {
    _unlink(path)
}

#[unsafe(no_mangle)]
pub extern "C" fn _rename(old_path: *const c_char, new_path: *const c_char) -> c_int {
    if old_path.is_null() || new_path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = (|| {
        let _ = syscall_errno(syscall::raw_syscall4(
            syscall::SyscallNumber::FileRename,
            AT_FDCWD as u64,
            old_path as u64,
            AT_FDCWD as u64,
            new_path as u64,
        ))?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn rename(old_path: *const c_char, new_path: *const c_char) -> c_int {
    _rename(old_path, new_path)
}

#[unsafe(no_mangle)]
pub extern "C" fn _execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = execve_raw(path, argv, envp);
    result_with_errno(result.map(|()| 0), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn execve(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    _execve(path, argv, envp)
}

#[unsafe(no_mangle)]
pub extern "C" fn _waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int {
    let result = (|| {
        if options & !WNOHANG != 0 {
            return Err(EINVAL);
        }
        let waited = syscall_errno(syscall::raw_syscall3(
            syscall::SyscallNumber::ProcessWait,
            pid as i64 as u64,
            status as u64,
            options as u64,
        ))?;
        Ok(waited as c_int)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int {
    _waitpid(pid, status, options)
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawn_file_actions_init(
    actions: *mut *mut PosixSpawnFileActions,
) -> c_int {
    if actions.is_null() {
        return EINVAL;
    }
    match unsafe { allocate_file_actions_object() } {
        Ok(value) => {
            // Safety: actions points to writable caller storage.
            unsafe { *actions = value };
            0
        }
        Err(errno_value) => errno_value,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawn_file_actions_destroy(
    actions: *mut *mut PosixSpawnFileActions,
) -> c_int {
    if actions.is_null() {
        return EINVAL;
    }
    // Safety: actions points to the caller's handle storage.
    let actions_ptr = unsafe { *actions };
    if actions_ptr.is_null() {
        return EINVAL;
    }
    // Safety: actions_ptr is the queue object previously allocated by init().
    let mut current = unsafe { (*actions_ptr).fa_list.stqh_first };
    while !current.is_null() {
        // Safety: current walks the action queue owned by actions_ptr.
        let next = unsafe { (*current).fae_list.stqe_next };
        unsafe { release_file_action_entry(current) };
        current = next;
    }
    unsafe {
        init_file_actions_list(actions_ptr);
        release_file_actions_object(actions_ptr);
        *actions = ptr::null_mut();
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawn_file_actions_addclose(
    actions: *mut *mut PosixSpawnFileActions,
    fildes: c_int,
) -> c_int {
    if actions.is_null() {
        return EINVAL;
    }
    if fildes < 0 {
        return EBADF;
    }
    // Safety: actions points to the caller's handle storage.
    let actions_ptr = unsafe { *actions };
    if actions_ptr.is_null() {
        return EINVAL;
    }
    let entry = match unsafe { allocate_file_action_entry() } {
        Ok(value) => value,
        Err(errno_value) => return errno_value,
    };
    unsafe {
        (*entry).fae_action = FAE_CLOSE;
        (*entry).fae_fildes = fildes;
        append_file_action(actions_ptr, entry);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawn_file_actions_adddup2(
    actions: *mut *mut PosixSpawnFileActions,
    fildes: c_int,
    newfildes: c_int,
) -> c_int {
    if actions.is_null() {
        return EINVAL;
    }
    if fildes < 0 || newfildes < 0 {
        return EBADF;
    }
    // Safety: actions points to the caller's handle storage.
    let actions_ptr = unsafe { *actions };
    if actions_ptr.is_null() {
        return EINVAL;
    }
    let entry = match unsafe { allocate_file_action_entry() } {
        Ok(value) => value,
        Err(errno_value) => return errno_value,
    };
    unsafe {
        (*entry).fae_action = FAE_DUP2;
        (*entry).fae_fildes = fildes;
        (*entry).fae_data.dup2 = PosixSpawnFileActionDup2 { newfildes };
        append_file_action(actions_ptr, entry);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn _posix_spawn(
    pid: *mut c_int,
    path: *const c_char,
    file_actions: *const *mut PosixSpawnFileActions,
    attrp: *const *mut PosixSpawnAttr,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if pid.is_null() || path.is_null() {
        return EINVAL;
    }
    if let Err(errno_value) = unsupported_spawn_attr(attrp) {
        return errno_value;
    }

    let pid_ptr = pid;
    let file_actions_ptr = file_actions;
    let argv_ptr = argv;
    let envp_ptr = envp;

    let child_pid = match syscall_errno(syscall::RawSyscallResult::new(process_spawn_raw())) {
        Ok(value) => value,
        Err(errno_value) => return errno_value,
    };

    if child_pid == 0 {
        let mut desired_fds = clone_current_fd_table();
        if apply_spawn_file_actions(&mut desired_fds, file_actions_ptr).is_err() {
            process_exit(SPAWN_FAIL_EXIT_STATUS);
        }
        let mut fd_state = [0u8; MAX_FD_STATE_LEN];
        let fd_state_len = match serialize_fd_state(&desired_fds, &mut fd_state) {
            Ok(value) => value,
            Err(_) => process_exit(SPAWN_FAIL_EXIT_STATUS),
        };
        let mut env_ptrs = [ptr::null(); MAX_ENV_POINTERS];
        if collect_envp_with_fd_state(
            envp_ptr,
            fd_state[..fd_state_len].as_ptr().cast::<c_char>(),
            &mut env_ptrs,
        )
        .is_err()
        {
            process_exit(SPAWN_FAIL_EXIT_STATUS);
        }
        if execve_raw(path, argv_ptr, env_ptrs.as_ptr()).is_err() {
            process_exit(SPAWN_FAIL_EXIT_STATUS);
        }
        process_exit(SPAWN_FAIL_EXIT_STATUS);
    }

    // Safety: pid points to writable storage supplied by the caller.
    unsafe { *pid_ptr = child_pid as c_int };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawn(
    pid: *mut c_int,
    path: *const c_char,
    file_actions: *const *mut PosixSpawnFileActions,
    attrp: *const *mut PosixSpawnAttr,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    _posix_spawn(pid, path, file_actions, attrp, argv, envp)
}

#[unsafe(no_mangle)]
pub extern "C" fn _posix_spawnp(
    pid: *mut c_int,
    file: *const c_char,
    file_actions: *const *mut PosixSpawnFileActions,
    attrp: *const *mut PosixSpawnAttr,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if file.is_null() {
        return EFAULT;
    }
    let file_bytes = unsafe { c_bytes(file) };
    if !file_bytes.contains(&b'/') {
        return ENOSYS;
    }
    _posix_spawn(pid, file, file_actions, attrp, argv, envp)
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnp(
    pid: *mut c_int,
    file: *const c_char,
    file_actions: *const *mut PosixSpawnFileActions,
    attrp: *const *mut PosixSpawnAttr,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    _posix_spawnp(pid, file, file_actions, attrp, argv, envp)
}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_init(lock: *mut *mut LockOpaque) {
    unsafe {
        if !lock.is_null() {
            *lock = core::ptr::addr_of!(DUMMY_LOCK) as *mut LockOpaque;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_init_recursive(lock: *mut *mut LockOpaque) {
    __retarget_lock_init(lock);
}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_acquire(_lock: *mut LockOpaque) {}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_acquire_recursive(_lock: *mut LockOpaque) {}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_try_acquire(_lock: *mut LockOpaque) -> c_int {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_try_acquire_recursive(_lock: *mut LockOpaque) -> c_int {
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_release(_lock: *mut LockOpaque) {}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_release_recursive(_lock: *mut LockOpaque) {}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_close(_lock: *mut LockOpaque) {}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_close_recursive(_lock: *mut LockOpaque) {}
