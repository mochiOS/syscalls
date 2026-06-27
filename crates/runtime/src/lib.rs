#![no_std]
#![feature(alloc_error_handler)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

use mochi_user_syscall as syscall;

const PAGE_SIZE: usize = 4096;
const HEADER_SIZE: usize = 16;
const MAP_PRIVATE_ANON: u64 = 0x22;

#[repr(align(16))]
struct Zst([u8; 1]);

static ZST: Zst = Zst([0]);

#[derive(Clone, Copy)]
struct AllocationHeader {
    base: usize,
    len: usize,
}

impl AllocationHeader {
    fn write_to(ptr: *mut u8, header: AllocationHeader) {
        unsafe {
            let dst = ptr as *mut usize;
            dst.write_unaligned(header.base);
            dst.add(1).write_unaligned(header.len);
        }
    }

    fn read_from(ptr: *const u8) -> AllocationHeader {
        unsafe {
            let src = ptr as *const usize;
            AllocationHeader {
                base: src.read_unaligned(),
                len: src.add(1).read_unaligned(),
            }
        }
    }
}

fn align_up(value: usize, align: usize) -> Option<usize> {
    let mask = align.checked_sub(1)?;
    value.checked_add(mask).map(|v| v & !mask)
}

pub struct UserAllocator {
    pages_allocated: AtomicUsize,
}

impl UserAllocator {
    pub const fn new() -> Self {
        Self {
            pages_allocated: AtomicUsize::new(0),
        }
    }

    fn request_pages(&self, len: usize) -> Option<usize> {
        let pages = len.div_ceil(PAGE_SIZE);
        let bytes = pages.checked_mul(PAGE_SIZE)?;
        let ret = syscall::raw_syscall5(
            syscall::SyscallNumber::MemoryMap,
            0,
            bytes as u64,
            3,
            MAP_PRIVATE_ANON,
            0,
        )
        .raw();
        let signed = ret as i64;
        if signed < 0 {
            None
        } else {
            self.pages_allocated.fetch_add(pages, Ordering::Relaxed);
            Some(ret as usize)
        }
    }

    #[allow(unsafe_op_in_unsafe_fn)]
    unsafe fn release_pages(&self, base: usize, len: usize) {
        let _ = syscall::raw_syscall2(syscall::SyscallNumber::MemoryUnmap, base as u64, len as u64);
        let pages = len.div_ceil(PAGE_SIZE);
        self.pages_allocated.fetch_sub(pages, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for UserAllocator {
    #[allow(unsafe_op_in_unsafe_fn)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            return core::ptr::addr_of!(ZST.0) as *mut u8;
        }
        let align = layout.align().max(core::mem::align_of::<usize>());
        let need = match layout.size().checked_add(HEADER_SIZE + align) {
            Some(v) => v,
            None => return core::ptr::null_mut(),
        };
        let base = match self.request_pages(need) {
            Some(v) => v,
            None => return core::ptr::null_mut(),
        };
        let user = match align_up(base + HEADER_SIZE, align) {
            Some(v) => v,
            None => {
                self.release_pages(base, need);
                return core::ptr::null_mut();
            }
        };
        let header_ptr = (user - HEADER_SIZE) as *mut u8;
        AllocationHeader::write_to(
            header_ptr,
            AllocationHeader {
                base,
                len: need.div_ceil(PAGE_SIZE) * PAGE_SIZE,
            },
        );
        user as *mut u8
    }

    #[allow(unsafe_op_in_unsafe_fn)]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() == 0 {
            return;
        }
        let header_ptr = ptr.sub(HEADER_SIZE);
        let header = AllocationHeader::read_from(header_ptr);
        self.release_pages(header.base, header.len);
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: UserAllocator = UserAllocator::new();

fn emergency_stderr(message: &'static [u8]) {
    let _ = syscall::raw_syscall3(
        syscall::SyscallNumber::Write,
        2,
        message.as_ptr() as u64,
        message.len() as u64,
    );
}

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    emergency_stderr(b"user runtime: allocation failed\n");
    abort()
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    emergency_stderr(b"user runtime: panic\n");
    abort()
}

pub fn abort() -> ! {
    let _ = syscall::raw_syscall1(syscall::SyscallNumber::ProcessExit, 127);
    loop {
        core::hint::spin_loop();
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InitialStack<'a> {
    pub argc: usize,
    pub argv: &'a [*const u8],
    pub envp: &'a [*const u8],
    pub auxv: &'a [(usize, usize)],
}

impl<'a> InitialStack<'a> {
    #[allow(unsafe_op_in_unsafe_fn)]
    pub unsafe fn parse(sp: *const usize) -> Self {
        let argc = sp.read();
        let argv = sp.add(1) as *const *const u8;
        let mut cursor = argv;
        for _ in 0..argc {
            cursor = cursor.add(1);
        }
        let argv_slice = core::slice::from_raw_parts(argv, argc);
        let mut env_cursor = cursor;
        while !env_cursor.read().is_null() {
            env_cursor = env_cursor.add(1);
        }
        let env_len = env_cursor.offset_from(cursor) as usize;
        let env_slice = core::slice::from_raw_parts(cursor, env_len);
        let auxv_start = env_cursor.add(1) as *const (usize, usize);
        let mut aux_len = 0usize;
        loop {
            let pair = auxv_start.add(aux_len).read();
            if pair.0 == 0 && pair.1 == 0 {
                break;
            }
            aux_len += 1;
        }
        let aux_slice = core::slice::from_raw_parts(auxv_start, aux_len);
        Self {
            argc,
            argv: argv_slice,
            envp: env_slice,
            auxv: aux_slice,
        }
    }
}

pub fn main_from_stack(main: fn()) -> ! {
    main();
    abort()
}

pub extern "C" fn thread_trampoline(entry: extern "C" fn(*mut c_void) -> !, arg: *mut c_void) -> ! {
    entry(arg)
}

pub fn yield_now() {
    let _ = syscall::call0(syscall::SyscallNumber::ThreadYield);
}

pub fn process_exit(code: u64) -> ! {
    let _ = syscall::raw_syscall1(syscall::SyscallNumber::ProcessExit, code);
    abort()
}

pub fn write_all(fd: u64, mut bytes: &[u8]) -> syscall::SysResult<()> {
    while !bytes.is_empty() {
        let wrote = syscall::call3(
            syscall::SyscallNumber::Write,
            fd,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
        )?;
        if wrote == 0 {
            return Err(syscall::SysError::from_raw(syscall::EPIPE as i64));
        }
        let consumed = wrote as usize;
        if consumed > bytes.len() {
            return Err(syscall::SysError::from_raw(syscall::EIO as i64));
        }
        bytes = &bytes[consumed..];
    }
    Ok(())
}

pub fn stdout_write(bytes: &[u8]) -> syscall::SysResult<()> {
    write_all(1, bytes)
}

pub fn stderr_write(bytes: &[u8]) -> syscall::SysResult<()> {
    write_all(2, bytes)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    if dest.is_null() || src.is_null() || n == 0 {
        return dest;
    }
    // SAFETY: The caller promises non-overlapping readable/writable regions for memcpy.
    unsafe {
        let mut i = 0usize;
        let dst = dest.cast::<u8>();
        let src = src.cast::<u8>();
        while i < n {
            dst.add(i).write(src.add(i).read());
            i += 1;
        }
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    if dest.is_null() || src.is_null() || n == 0 {
        return dest;
    }
    // SAFETY: The caller provides valid readable/writable regions of n bytes.
    unsafe {
        let dst = dest.cast::<u8>();
        let src = src.cast::<u8>();
        if (dst as usize) <= (src as usize) || (dst as usize) >= (src as usize + n) {
            let mut i = 0usize;
            while i < n {
                dst.add(i).write(src.add(i).read());
                i += 1;
            }
        } else {
            let mut i = n;
            while i != 0 {
                i -= 1;
                dst.add(i).write(src.add(i).read());
            }
        }
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dest: *mut c_void, value: i32, n: usize) -> *mut c_void {
    if dest.is_null() || n == 0 {
        return dest;
    }
    // SAFETY: The caller provides a valid writable region of n bytes.
    unsafe {
        let mut i = 0usize;
        let dst = dest.cast::<u8>();
        let byte = value as u8;
        while i < n {
            dst.add(i).write(byte);
            i += 1;
        }
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> i32 {
    if n == 0 {
        return 0;
    }
    if a.is_null() || b.is_null() {
        return 1;
    }
    // SAFETY: The caller provides valid readable regions of n bytes.
    let left = unsafe { core::slice::from_raw_parts(a.cast::<u8>(), n) };
    let right = unsafe { core::slice::from_raw_parts(b.cast::<u8>(), n) };
    for (lhs, rhs) in left.iter().zip(right.iter()) {
        if lhs != rhs {
            return *lhs as i32 - *rhs as i32;
        }
    }
    0
}
