#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use core::fmt::{self, Write};

pub use mnu_abi::DmaAllocation;
pub use mochi_user_runtime as runtime;
pub use mochi_user_syscall as syscall;

pub mod path {
    use super::syscall::{self, SysError, SysResult};

    pub struct CPath<const N: usize> {
        buf: [u8; N],
    }

    impl<const N: usize> CPath<N> {
        pub fn new(path: &str) -> SysResult<Self> {
            let bytes = path.as_bytes();
            if bytes.len() + 1 > N {
                return Err(SysError::from_raw(syscall::EINVAL as i64));
            }
            let mut buf = [0u8; N];
            buf[..bytes.len()].copy_from_slice(bytes);
            buf[bytes.len()] = 0;
            Ok(Self { buf })
        }

        pub fn as_ptr(&self) -> u64 {
            self.buf.as_ptr() as u64
        }
    }
}

pub mod io {
    use super::syscall::SysResult;

    pub const STDIN: u64 = 0;
    pub const STDOUT: u64 = 1;
    pub const STDERR: u64 = 2;

    pub fn write(fd: u64, bytes: &[u8]) -> SysResult<()> {
        super::runtime::write_all(fd, bytes)
    }

    pub fn stdout(bytes: &[u8]) -> SysResult<()> {
        write(STDOUT, bytes)
    }

    pub fn stderr(bytes: &[u8]) -> SysResult<()> {
        write(STDERR, bytes)
    }
}

pub mod logger {
    use super::{Write, alloc, ipc, runtime, syscall};
    use core::fmt;
    use core::sync::atomic::{AtomicU64, Ordering};

    static LOGGER_ENDPOINT: AtomicU64 = AtomicU64::new(0);

    fn parse_decimal_u64(bytes: &[u8]) -> Option<u64> {
        if bytes.is_empty() {
            return None;
        }
        let mut out = 0u64;
        for &b in bytes {
            if !b.is_ascii_digit() {
                return None;
            }
            out = out.checked_mul(10)?;
            out = out.checked_add(u64::from(b - b'0'))?;
        }
        Some(out)
    }

    unsafe fn c_string_len(ptr: *const u8) -> usize {
        let mut len = 0usize;
        loop {
            let ch = unsafe { core::ptr::read_volatile(ptr.add(len)) };
            if ch == 0 {
                return len;
            }
            len += 1;
        }
    }

    pub fn init(endpoint: u64) {
        LOGGER_ENDPOINT.store(endpoint, Ordering::Relaxed);
    }

    pub fn endpoint() -> Option<u64> {
        let endpoint = LOGGER_ENDPOINT.load(Ordering::Relaxed);
        if endpoint == 0 { None } else { Some(endpoint) }
    }

    pub unsafe fn init_from_initial_stack(sp: *const usize) -> Option<u64> {
        let stack = unsafe { runtime::InitialStack::parse(sp) };
        let mut last_numeric = None;
        for &arg_ptr in stack.argv {
            if arg_ptr.is_null() {
                continue;
            }
            let len = unsafe { c_string_len(arg_ptr) };
            let arg = unsafe { core::slice::from_raw_parts(arg_ptr, len) };
            crate::service_ready::capture_bootstrap_arg(arg);
            if let Some(value) = parse_decimal_u64(arg) {
                last_numeric = Some(value);
            }
        }
        if let Some(endpoint) = last_numeric {
            init(endpoint);
        }
        last_numeric
    }

    pub fn write_fmt(args: fmt::Arguments<'_>) -> syscall::SysResult<()> {
        if let Some(endpoint) = endpoint() {
            let mut buf = alloc::string::String::new();
            buf.write_fmt(args)
                .map_err(|_| syscall::SysError::from_raw(syscall::EINVAL as i64))?;
            let _ = ipc::send(endpoint, buf.as_bytes());
            Ok(())
        } else {
            super::write_fmt(super::io::STDOUT, args)
        }
    }
}

struct FmtWriter(u64);

impl Write for FmtWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        io::write(self.0, s.as_bytes()).map_err(|_| fmt::Error)
    }
}

pub fn write_fmt(fd: u64, args: fmt::Arguments<'_>) -> syscall::SysResult<()> {
    let mut writer = FmtWriter(fd);
    writer
        .write_fmt(args)
        .map_err(|_| syscall::SysError::from_raw(syscall::EINVAL as i64))
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        let _ = $crate::logger::write_fmt(format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! println {
    () => {{
        let _ = $crate::logger::write_fmt(format_args!("\n"));
    }};
    ($($arg:tt)*) => {{
        let _ = $crate::logger::write_fmt(format_args!("{}\n", format_args!($($arg)*)));
    }};
}

pub mod thread {
    pub fn yield_now() {
        super::runtime::yield_now();
    }
}

pub mod process {
    use super::syscall::{self, SysResult};

    pub fn find_by_name(name: &str) -> SysResult<u64> {
        let bytes = name.as_bytes();
        syscall::call2(
            syscall::SyscallNumber::FindProcessByName,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
        )
    }

    pub fn exit(code: u64) -> ! {
        super::runtime::process_exit(code)
    }

    pub fn wait(pid: i64, status_ptr: u64, options: u64) -> SysResult<u64> {
        syscall::call3(
            syscall::SyscallNumber::ProcessWait,
            pid as u64,
            status_ptr,
            options,
        )
    }
}

pub mod ipc {
    use super::syscall::{self, SysResult};

    pub fn create() -> SysResult<u64> {
        syscall::call2(syscall::SyscallNumber::IpcCreate, 0, 0)
    }

    pub fn send(endpoint: u64, bytes: &[u8]) -> SysResult<u64> {
        syscall::call3(
            syscall::SyscallNumber::IpcSend,
            endpoint,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
        )
    }

    pub fn wait(endpoint: u64, buf: &mut [u8]) -> SysResult<u64> {
        syscall::call3(
            syscall::SyscallNumber::IpcWait,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            endpoint,
        )
    }

    pub fn try_wait(buf: &mut [u8]) -> SysResult<u64> {
        syscall::call3(
            syscall::SyscallNumber::IpcWait,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
        )
    }

    pub fn endpoint_alive(endpoint: u64) -> bool {
        syscall::call1(syscall::SyscallNumber::IpcEndpointAlive, endpoint).is_ok()
    }

    pub fn call(dest_thread_id: u64, request: &[u8], reply: &mut [u8]) -> SysResult<u64> {
        syscall::call5(
            syscall::SyscallNumber::IpcCall,
            dest_thread_id,
            request.as_ptr() as u64,
            request.len() as u64,
            reply.as_mut_ptr() as u64,
            reply.len() as u64,
        )
    }

    pub fn reply(sender_handle: u64, bytes: &[u8]) -> SysResult<u64> {
        syscall::call3(
            syscall::SyscallNumber::IpcReply,
            sender_handle,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
        )
    }

    pub fn send_pages(endpoint: u64, phys_pages: &[u64], local_base: u64) -> SysResult<u64> {
        syscall::call4(
            syscall::SyscallNumber::IpcSendPages,
            endpoint,
            0,
            phys_pages.len() as u64,
            local_base,
        )
    }

    pub fn send_page_count(endpoint: u64, page_count: usize, local_base: u64) -> SysResult<u64> {
        syscall::call4(
            syscall::SyscallNumber::IpcSendPages,
            endpoint,
            0,
            page_count as u64,
            local_base,
        )
    }
}

pub mod input {
    pub const RAW_KIND_KEYBOARD: u8 = 1;
    pub const RAW_KIND_MOUSE_PACKET: u8 = 2;
    pub const RAW_KIND_POINTER_ABSOLUTE: u8 = 3;

    pub const EVENT_KIND_KEY: u16 = 1;
    pub const EVENT_KIND_POINTER_MOVE: u16 = 2;
    pub const EVENT_KIND_POINTER_BUTTON: u16 = 3;
    pub const EVENT_KIND_POINTER_WHEEL: u16 = 4;
    pub const EVENT_KIND_POINTER_ABSOLUTE: u16 = 5;

    pub const FLAG_PRESS: u16 = 1 << 0;
    pub const FLAG_RELEASE: u16 = 1 << 1;

    pub const MOD_SHIFT: u32 = 1 << 0;
    pub const MOD_CTRL: u32 = 1 << 1;
    pub const MOD_ALT: u32 = 1 << 2;
    pub const MOD_CAPS_LOCK: u32 = 1 << 3;

    pub const KEY_ESC: u16 = 1;
    pub const KEY_BACKSPACE: u16 = 2;
    pub const KEY_TAB: u16 = 3;
    pub const KEY_ENTER: u16 = 4;
    pub const KEY_SPACE: u16 = 5;
    pub const KEY_LEFT_SHIFT: u16 = 6;
    pub const KEY_RIGHT_SHIFT: u16 = 7;
    pub const KEY_LEFT_CTRL: u16 = 8;
    pub const KEY_RIGHT_CTRL: u16 = 9;
    pub const KEY_LEFT_ALT: u16 = 10;
    pub const KEY_RIGHT_ALT: u16 = 11;
    pub const KEY_CAPS_LOCK: u16 = 12;
    pub const KEY_A: u16 = 32;
    pub const KEY_B: u16 = 33;
    pub const KEY_C: u16 = 34;
    pub const KEY_D: u16 = 35;
    pub const KEY_E: u16 = 36;
    pub const KEY_F: u16 = 37;
    pub const KEY_G: u16 = 38;
    pub const KEY_H: u16 = 39;
    pub const KEY_I: u16 = 40;
    pub const KEY_J: u16 = 41;
    pub const KEY_K: u16 = 42;
    pub const KEY_L: u16 = 43;
    pub const KEY_M: u16 = 44;
    pub const KEY_N: u16 = 45;
    pub const KEY_O: u16 = 46;
    pub const KEY_P: u16 = 47;
    pub const KEY_Q: u16 = 48;
    pub const KEY_R: u16 = 49;
    pub const KEY_S: u16 = 50;
    pub const KEY_T: u16 = 51;
    pub const KEY_U: u16 = 52;
    pub const KEY_V: u16 = 53;
    pub const KEY_W: u16 = 54;
    pub const KEY_X: u16 = 55;
    pub const KEY_Y: u16 = 56;
    pub const KEY_Z: u16 = 57;
    pub const KEY_0: u16 = 58;
    pub const KEY_1: u16 = 59;
    pub const KEY_2: u16 = 60;
    pub const KEY_3: u16 = 61;
    pub const KEY_4: u16 = 62;
    pub const KEY_5: u16 = 63;
    pub const KEY_6: u16 = 64;
    pub const KEY_7: u16 = 65;
    pub const KEY_8: u16 = 66;
    pub const KEY_9: u16 = 67;
    pub const KEY_MINUS: u16 = 68;
    pub const KEY_EQUAL: u16 = 69;
    pub const KEY_LEFT_BRACKET: u16 = 70;
    pub const KEY_RIGHT_BRACKET: u16 = 71;
    pub const KEY_SEMICOLON: u16 = 72;
    pub const KEY_APOSTROPHE: u16 = 73;
    pub const KEY_GRAVE: u16 = 74;
    pub const KEY_BACKSLASH: u16 = 75;
    pub const KEY_COMMA: u16 = 76;
    pub const KEY_DOT: u16 = 77;
    pub const KEY_SLASH: u16 = 78;
    pub const KEY_DELETE: u16 = 79;
    pub const KEY_HOME: u16 = 80;
    pub const KEY_END: u16 = 81;
    pub const KEY_LEFT: u16 = 82;
    pub const KEY_RIGHT: u16 = 83;
    pub const KEY_UP: u16 = 84;
    pub const KEY_DOWN: u16 = 85;
    pub const KEY_PAGE_UP: u16 = 86;
    pub const KEY_PAGE_DOWN: u16 = 87;

    pub const POINTER_BUTTON_LEFT: u16 = 1;
    pub const POINTER_BUTTON_RIGHT: u16 = 2;
    pub const POINTER_BUTTON_MIDDLE: u16 = 3;

    pub const SUBSCRIBE_OPCODE: u32 = 0x5355_4253;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct RawInputPacket {
        pub kind: u8,
        pub reserved: [u8; 3],
        pub data: [u8; 4],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct SubscribeRequest {
        pub opcode: u32,
        pub reserved: u32,
        pub endpoint: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct InputEvent {
        pub kind: u16,
        pub flags: u16,
        pub keycode: u16,
        pub detail: u16,
        pub codepoint: u32,
        pub value_x: i32,
        pub value_y: i32,
        pub value_z: i32,
        pub modifiers: u32,
        pub reserved: u32,
    }

    pub fn bytes_of<T>(value: &T) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts((value as *const T).cast::<u8>(), core::mem::size_of::<T>())
        }
    }
}

pub mod service {
    use super::syscall::{self, SysResult};
    pub const DELEGATE_SERVICE_SPAWN: u64 = 1;
    pub const DELEGATE_DRIVER_SPAWN: u64 = 2;
    pub const ROLE_CORE_SERVICE: u64 = 1;
    pub const ROLE_SERVICE: u64 = 2;
    pub const ROLE_APPLICATION: u64 = 3;
    pub const ROLE_DRIVER: u64 = 4;
    pub const ROLE_TOOL: u64 = 5;
    pub const ROLE_UNKNOWN: u64 = 6;

    pub fn spawn(path: &str) -> SysResult<u64> {
        let path = super::path::CPath::<256>::new(path)?;
        syscall::call1(syscall::SyscallNumber::ServiceSpawn, path.as_ptr())
    }

    pub fn spawn_driver(path: &str) -> SysResult<u64> {
        let path = super::path::CPath::<256>::new(path)?;
        syscall::call1(syscall::SyscallNumber::DriverSpawn, path.as_ptr())
    }

    pub fn spawn_manifest(
        path: &str,
        role: u64,
        args_nul: Option<&[u8]>,
        caps_nul: Option<&[u8]>,
    ) -> SysResult<u64> {
        let path = super::path::CPath::<256>::new(path)?;
        let (args_ptr, _args_len) = match args_nul {
            Some(bytes) if !bytes.is_empty() => (bytes.as_ptr() as u64, bytes.len() as u64),
            _ => (0, 0),
        };
        let (caps_ptr, caps_len) = match caps_nul {
            Some(bytes) if !bytes.is_empty() => (bytes.as_ptr() as u64, bytes.len() as u64),
            _ => (0, 0),
        };
        syscall::call5(
            syscall::SyscallNumber::ExecManifest,
            path.as_ptr(),
            args_ptr,
            caps_ptr,
            caps_len,
            role,
        )
    }

    pub fn register_delegate(kind: u64, pid: u64) -> SysResult<u64> {
        syscall::call2(syscall::SyscallNumber::ServiceDelegateRegister, kind, pid)
    }
}

pub mod service_ready;

pub mod time {
    use super::syscall::{self, SysResult};

    pub fn ticks() -> SysResult<u64> {
        syscall::call0(syscall::SyscallNumber::TimeNow)
    }

    pub fn utc_seconds() -> SysResult<u64> {
        let mut timespec = [0i64; 2];
        syscall::call2(
            syscall::SyscallNumber::ClockGettime,
            0,
            timespec.as_mut_ptr() as u64,
        )?;
        u64::try_from(timespec[0]).map_err(|_| syscall::SysError::from_raw(syscall::EIO as i64))
    }
}

pub mod random {
    use super::syscall::{self, SysResult};

    pub fn fill(destination: &mut [u8]) -> SysResult<()> {
        let written = syscall::call2(
            syscall::SyscallNumber::RandomFill,
            destination.as_mut_ptr() as u64,
            destination.len() as u64,
        )?;
        if written != destination.len() as u64 {
            return Err(syscall::SysError::from_raw(syscall::EIO as i64));
        }
        Ok(())
    }
}

pub mod port {
    use super::syscall::{self, SysResult};

    pub fn in_u8(port: u16) -> SysResult<u8> {
        syscall::call2(syscall::SyscallNumber::PortIn, port as u64, 1).map(|v| v as u8)
    }

    pub fn out_u8(port: u16, value: u8) -> SysResult<u64> {
        syscall::call3(
            syscall::SyscallNumber::PortOut,
            port as u64,
            value as u64,
            1,
        )
    }
}

pub mod memory {
    use super::syscall::{self, SysResult};
    use crate::DmaAllocation;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct FramebufferInfo {
        pub addr: u64,
        pub size: u64,
        pub width: u32,
        pub height: u32,
        pub stride: u32,
        pub format: u32,
    }

    pub fn mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64) -> SysResult<u64> {
        syscall::call5(
            syscall::SyscallNumber::MemoryMap,
            addr,
            len,
            prot,
            flags,
            fd,
        )
    }

    pub fn munmap(addr: u64, len: u64) -> SysResult<u64> {
        syscall::call2(syscall::SyscallNumber::MemoryUnmap, addr, len)
    }

    pub fn map_physical_range(virt: u64, phys: u64, len: u64) -> SysResult<u64> {
        syscall::call3(syscall::SyscallNumber::MapPhysicalRange, virt, phys, len)
    }

    pub fn framebuffer_info() -> SysResult<FramebufferInfo> {
        let mut info = FramebufferInfo::default();
        syscall::call1(
            syscall::SyscallNumber::GetFramebufferInfo,
            (&mut info as *mut FramebufferInfo) as u64,
        )?;
        Ok(info)
    }

    pub fn map_framebuffer(virt: u64, len: u64) -> SysResult<u64> {
        syscall::call2(syscall::SyscallNumber::MapFramebuffer, virt, len)
    }

    pub fn get_physical_addr(virt: u64) -> SysResult<u64> {
        syscall::call1(syscall::SyscallNumber::GetPhysicalAddr, virt)
    }

    pub fn alloc_shared_pages(phys_pages: &mut [u64]) -> SysResult<u64> {
        syscall::call4(
            syscall::SyscallNumber::AllocSharedPages,
            phys_pages.len() as u64,
            phys_pages.as_mut_ptr() as u64,
            phys_pages.len() as u64,
            0,
        )
    }

    pub fn alloc_shared_page_count(page_count: usize) -> SysResult<u64> {
        syscall::call4(
            syscall::SyscallNumber::AllocSharedPages,
            page_count as u64,
            0,
            0,
            0,
        )
    }

    pub fn dma_alloc(len: u64) -> SysResult<DmaAllocation> {
        let mut alloc = DmaAllocation::default();
        syscall::call2(
            syscall::SyscallNumber::DmaAlloc,
            len,
            (&mut alloc as *mut DmaAllocation) as u64,
        )?;
        Ok(alloc)
    }

    pub fn dma_free(handle: u64) -> SysResult<u64> {
        syscall::call1(syscall::SyscallNumber::DmaFree, handle)
    }
}

pub mod file {
    use super::syscall::{self, SysResult};
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;

    pub fn open(path_ptr: u64, flags: u64) -> SysResult<u64> {
        syscall::call2(syscall::SyscallNumber::FileOpen, path_ptr, flags)
    }

    pub fn open_path(path: &str, flags: u64) -> SysResult<u64> {
        let path = super::path::CPath::<256>::new(path)?;
        open(path.as_ptr(), flags)
    }

    pub fn openat(dirfd: i64, path_ptr: u64, flags: u64, mode: u64) -> SysResult<u64> {
        syscall::call4(
            syscall::SyscallNumber::FileOpenAt,
            dirfd as u64,
            path_ptr,
            flags,
            mode,
        )
    }

    pub fn openat_path(dirfd: i64, path: &str, flags: u64, mode: u64) -> SysResult<u64> {
        let path = super::path::CPath::<256>::new(path)?;
        openat(dirfd, path.as_ptr(), flags, mode)
    }

    pub fn close(fd: u64) -> SysResult<u64> {
        syscall::call1(syscall::SyscallNumber::FileClose, fd)
    }

    pub fn read(fd: u64, buf_ptr: u64, len: u64) -> SysResult<u64> {
        syscall::call3(syscall::SyscallNumber::FileRead, fd, buf_ptr, len)
    }

    pub fn write(fd: u64, buf_ptr: u64, len: u64) -> SysResult<u64> {
        syscall::call3(syscall::SyscallNumber::FileWrite, fd, buf_ptr, len)
    }

    pub fn seek(fd: u64, offset: i64, whence: u64) -> SysResult<u64> {
        syscall::call3(syscall::SyscallNumber::FileSeek, fd, offset as u64, whence)
    }

    pub fn create_dir(path: &str, mode: u64) -> SysResult<u64> {
        let path = super::path::CPath::<256>::new(path)?;
        syscall::call2(syscall::SyscallNumber::FileCreateDir, path.as_ptr(), mode)
    }

    pub fn remove(path: &str) -> SysResult<u64> {
        let path = super::path::CPath::<256>::new(path)?;
        syscall::call1(syscall::SyscallNumber::FileRemove, path.as_ptr())
    }

    pub fn rename(src: &str, dst: &str) -> SysResult<u64> {
        let src = super::path::CPath::<256>::new(src)?;
        let dst = super::path::CPath::<256>::new(dst)?;
        syscall::call4(
            syscall::SyscallNumber::FileRename,
            (-100i64) as u64,
            src.as_ptr(),
            (-100i64) as u64,
            dst.as_ptr(),
        )
    }

    pub fn read_to_end_path(path: &str) -> SysResult<Vec<u8>> {
        let fd = open_path(path, 0)?;
        let mut out = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let read = match read(fd, buf.as_mut_ptr() as u64, buf.len() as u64) {
                Ok(read) => read,
                Err(err) => {
                    let _ = close(fd);
                    return Err(err);
                }
            };
            if read == 0 {
                break;
            }
            out.extend_from_slice(&buf[..read as usize]);
            if (read as usize) < buf.len() {
                break;
            }
        }
        let _ = close(fd);
        Ok(out)
    }

    pub fn read_dir_names(path: &str) -> SysResult<Vec<String>> {
        let fd = open_path(path, 0)?;
        let mut out = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let read = syscall::call3(
                syscall::SyscallNumber::FileReadDir,
                fd,
                buf.as_mut_ptr() as u64,
                buf.len() as u64,
            )?;
            if read == 0 {
                break;
            }
            let mut offset = 0usize;
            let read = read as usize;
            while offset + 19 <= read {
                let reclen = u16::from_ne_bytes([buf[offset + 16], buf[offset + 17]]) as usize;
                if reclen == 0 || offset + reclen > read {
                    break;
                }
                let name_start = offset + 19;
                let name_end = offset + reclen;
                let name_bytes = &buf[name_start..name_end];
                let name_len = name_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(name_bytes.len());
                if name_len > 0
                    && let Ok(name) = core::str::from_utf8(&name_bytes[..name_len])
                    && name != "."
                    && name != ".."
                {
                    out.push(name.to_string());
                }
                offset += reclen;
            }
            if (read as usize) < buf.len() {
                break;
            }
        }
        let _ = close(fd);
        Ok(out)
    }
}

pub mod event {
    use super::syscall::{self, SysResult};

    pub fn create(flags: u64) -> SysResult<u64> {
        syscall::call2(syscall::SyscallNumber::EventCreate, flags, 0)
    }

    pub fn wait(event_id: u64, timeout_ms: u64) -> SysResult<u64> {
        syscall::call3(syscall::SyscallNumber::EventWait, event_id, timeout_ms, 0)
    }

    pub fn signal(event_id: u64) -> SysResult<u64> {
        syscall::call3(syscall::SyscallNumber::EventSignal, event_id, 0, 0)
    }

    pub fn poll(events_ptr: u64, count: u64, timeout_ms: u64) -> SysResult<u64> {
        syscall::call3(
            syscall::SyscallNumber::EventPoll,
            events_ptr,
            count,
            timeout_ms,
        )
    }
}

pub mod capability {
    use super::syscall::{self, SysResult};
    pub use mochios_capability_protocol::{
        CAPABILITY_DECISION_OPCODE, CAPABILITY_PERSISTENT_QUERY_OPCODE, CAPABILITY_PROMPT_OPCODE,
        CAPABILITY_RESPONSE_OPCODE, CapabilityClass, CapabilityDecision, CapabilityDecisionRequest,
        CapabilityRequest, ExecutableIdentity, MAX_CAPABILITY_NAME_LEN, MAX_DECISION_PAYLOAD_SIZE,
        MAX_EXECUTABLE_PATH_LEN, MAX_PAYLOAD_SIZE, MAX_REASON_LEN, MAX_RESOURCE_PATH_LEN,
        PROTOCOL_VERSION, ProtocolError, RESOLVE_CAPABILITIES_OPCODE,
        RESOLVE_CAPABILITIES_REPLY_STATUS_LEN, RESOLVE_CAPABILITIES_REQUEST_PREFIX_LEN,
        ResolveCapabilitiesReply, ResourceDescriptor, decode_decision_request, decode_request,
        decode_resolve_capabilities_reply, decode_resolve_capabilities_request,
        encode_decision_request, encode_request, encode_resolve_capabilities_reply,
        encode_resolve_capabilities_request,
    };

    pub fn capability_from_string(name: &str) -> CapabilityClass {
        match name {
            "fs.read.user.documents"
            | "fs.write.user.documents"
            | "fs.read.user.downloads"
            | "fs.write.user.downloads"
            | "fs.read.user.desktop"
            | "fs.write.user.desktop"
            | "fs.read.user.pictures"
            | "fs.write.user.pictures"
            | "fs.read.user.music"
            | "fs.write.user.music"
            | "fs.read.user.videos"
            | "fs.write.user.videos"
            | "fs.read.user"
            | "fs.write.user"
            | "fs.read.tmp"
            | "fs.write.tmp"
            | "fs.read.removable"
            | "fs.write.removable"
            | "net.connect"
            | "net.listen"
            | "net.tls.connect"
            | "net.http.request"
            | "window.create"
            | "window.overlay"
            | "display.read"
            | "input.keyboard"
            | "input.pointer"
            | "audio.playback"
            | "audio.record"
            | "clipboard.read"
            | "clipboard.write"
            | "notification.send"
            | "system.time.read"
            | "system.info.read"
            | "system.logs.read"
            | "account.self.read"
            | "account.self.modify"
            | "settings.read" => CapabilityClass::UserGrantable,
            "fs.read.all"
            | "fs.write.all"
            | "net.raw"
            | "window.decorate"
            | "window.capture"
            | "display.capture"
            | "input.keyboard.global"
            | "input.pointer.global"
            | "input.gamepad"
            | "camera.access"
            | "microphone.access"
            | "location.access"
            | "bluetooth.access"
            | "usb.access"
            | "serial.access"
            | "power.shutdown"
            | "power.reboot"
            | "power.suspend"
            | "system.time.set"
            | "package.install"
            | "package.remove"
            | "package.update"
            | "service.register"
            | "service.control"
            | "vm.create"
            | "vm.control"
            | "device.gpu"
            | "device.audio"
            | "device.input"
            | "device.storage"
            | "device.net"
            | "account.other.read"
            | "account.other.modify"
            | "settings.write" => CapabilityClass::Privileged,
            "system.random.read" => CapabilityClass::SystemOnly,
            _ => CapabilityClass::SystemOnly,
        }
    }

    pub fn query(ptr: u64, len: u64) -> SysResult<u64> {
        syscall::call2(syscall::SyscallNumber::CapQuery, ptr, len)
    }

    pub fn check_thread(thread_id: u64, capability: &str) -> SysResult<u64> {
        let bytes = capability.as_bytes();
        syscall::call3(
            syscall::SyscallNumber::CheckThreadCapability,
            thread_id,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
        )
    }
}

pub mod env {
    use super::syscall::{ENOSYS, SysError, SysResult};

    pub fn args() -> SysResult<&'static [&'static [u8]]> {
        Err(SysError::from_raw(ENOSYS as i64))
    }
}

pub mod package;
