#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use core::fmt::{self, Write};

pub use mochi_user_runtime as runtime;
pub use mochi_user_syscall as syscall;
pub use mnu_abi::DmaAllocation;

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
        let _ = $crate::write_fmt($crate::io::STDOUT, format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! println {
    () => {{
        let _ = $crate::write_fmt($crate::io::STDOUT, format_args!("\n"));
    }};
    ($($arg:tt)*) => {{
        let _ = $crate::write_fmt($crate::io::STDOUT, format_args!("{}\n", format_args!($($arg)*)));
    }};
}

pub mod thread {
    pub fn yield_now() {
        super::runtime::yield_now();
    }
}

pub mod process {
    pub fn exit(code: u64) -> ! {
        super::runtime::process_exit(code)
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

pub mod time {
    use super::syscall::{self, SysResult};

    pub fn ticks() -> SysResult<u64> {
        syscall::call0(syscall::SyscallNumber::GetTicks)
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

    pub fn get_physical_addr(virt: u64) -> SysResult<u64> {
        syscall::call1(syscall::SyscallNumber::GetPhysicalAddr, virt)
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

    pub fn read_to_end_path(path: &str) -> SysResult<Vec<u8>> {
        let fd = open_path(path, 0)?;
        let mut out = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let read = read(fd, buf.as_mut_ptr() as u64, buf.len() as u64)?;
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

    pub fn query(ptr: u64, len: u64) -> SysResult<u64> {
        syscall::call2(syscall::SyscallNumber::CapQuery, ptr, len)
    }
}

pub mod env {
    use super::syscall::{SysError, SysResult, ENOSYS};

    pub fn args() -> SysResult<&'static [&'static [u8]]> {
        Err(SysError::from_raw(ENOSYS as i64))
    }
}
