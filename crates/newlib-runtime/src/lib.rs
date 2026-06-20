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
    static _end: u8;

    fn main(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) -> c_int;
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

unsafe fn initialize_runtime(stack: StackView) {
    let state = unsafe { state_mut() };
    if state.initialized {
        return;
    }

    state.initialized = true;
    state.argv = stack.argv;
    state.envp = stack.envp;
    state.fds[0] = FdEntry::stdio(0, FdKind::Stdin);
    state.fds[1] = FdEntry::stdio(1, FdKind::Stdout);
    state.fds[2] = FdEntry::stdio(2, FdKind::Stderr);

    let heap_base = align_up(ptr::addr_of!(_end) as usize, PAGE_SIZE).unwrap_or(PAGE_SIZE);
    let stack_limit = align_down(stack.stack_top, PAGE_SIZE).saturating_sub(PAGE_SIZE);
    state.heap = HeapState {
        initialized: true,
        base: heap_base,
        current_break: heap_base,
        mapped_end: heap_base,
        maximum_end: stack_limit.max(heap_base),
        page_size: PAGE_SIZE,
    };

    unsafe {
        environ = stack.envp;
        __env = stack.envp;
    }
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
    unsafe {
        call_init_array(
            ptr::addr_of!(__fini_array_start),
            ptr::addr_of!(__fini_array_end),
        )
    };
    _exit(code)
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

#[unsafe(export_name = "write")]
pub extern "C" fn write_alias(fd: c_int, buffer: *const c_void, length: usize) -> isize {
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

#[unsafe(export_name = "read")]
pub extern "C" fn read_alias(fd: c_int, buffer: *mut c_void, length: usize) -> isize {
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

#[unsafe(export_name = "open")]
pub extern "C" fn open_alias(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
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

#[unsafe(export_name = "close")]
pub extern "C" fn close_alias(fd: c_int) -> c_int {
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

#[unsafe(export_name = "lseek")]
pub extern "C" fn lseek_alias(fd: c_int, offset: i64, whence: c_int) -> i64 {
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
        let _ = syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::FileFstat,
            entry.lower_handle,
            stat_buf as u64,
        ))?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(export_name = "fstat")]
pub extern "C" fn fstat_alias(fd: c_int, stat_buf: *mut c_void) -> c_int {
    _fstat(fd, stat_buf)
}

#[unsafe(no_mangle)]
pub extern "C" fn _stat(path: *const c_char, stat_buf: *mut c_void) -> c_int {
    if path.is_null() || stat_buf.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = (|| {
        let _ = syscall_errno(syscall::raw_syscall4(
            syscall::SyscallNumber::FileStatAt,
            AT_FDCWD as u64,
            path as u64,
            stat_buf as u64,
            0,
        ))?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(export_name = "stat")]
pub extern "C" fn stat_alias(path: *const c_char, stat_buf: *mut c_void) -> c_int {
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

#[unsafe(export_name = "isatty")]
pub extern "C" fn isatty_alias(fd: c_int) -> c_int {
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

#[unsafe(export_name = "sbrk")]
pub extern "C" fn sbrk_alias(increment: isize) -> *mut c_void {
    _sbrk(increment)
}

#[unsafe(no_mangle)]
pub extern "C" fn _getpid() -> c_int {
    set_errno(ENOSYS);
    -1
}

#[unsafe(export_name = "getpid")]
pub extern "C" fn getpid_alias() -> c_int {
    _getpid()
}

#[unsafe(no_mangle)]
pub extern "C" fn _kill(_pid: c_int, _sig: c_int) -> c_int {
    set_errno(ENOSYS);
    -1
}

#[unsafe(export_name = "kill")]
pub extern "C" fn kill_alias(pid: c_int, sig: c_int) -> c_int {
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

#[unsafe(export_name = "times")]
pub extern "C" fn times_alias(buf: *mut Tms) -> i64 {
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

#[unsafe(export_name = "unlink")]
pub extern "C" fn unlink_alias(path: *const c_char) -> c_int {
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

#[unsafe(export_name = "rename")]
pub extern "C" fn rename_alias(old_path: *const c_char, new_path: *const c_char) -> c_int {
    _rename(old_path, new_path)
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
