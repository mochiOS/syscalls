#![no_std]

extern crate alloc;

#[cfg(feature = "mboot-wifi")]
pub mod mboot_wifi;
pub mod session_control;
pub mod diagnostic;
pub mod memory_object;
mod handle_result;
pub mod workspace;
#[cfg(any(feature = "std", test))]
extern crate std;

#[cfg(all(feature = "runtime", feature = "std"))]
compile_error!("features `runtime` and `std` are mutually exclusive");
// With neither startup feature, the embedding program supplies its allocator
// and panic handler. Native Handle/IPC helpers do not require a runtime.

use core::fmt::{self, Write};

pub use mnu_abi::DmaAllocation;
#[cfg(feature = "runtime")]
pub use mochi_user_runtime as runtime;
pub use mochi_user_syscall as syscall;

#[cfg(feature = "runtime")]
use runtime as runtime_support;

#[cfg(not(feature = "runtime"))]
mod runtime_support {
    use super::syscall;

    pub fn write_all(fd: u64, bytes: &[u8]) -> syscall::SysResult<()> {
        if fd != 1 && fd != 2 {
            return Err(syscall::SysError::from_raw(syscall::EBADF as i64));
        }
        if !bytes.is_empty() {
            let wrote = syscall::call2(
                syscall::SyscallNumber::DebugWrite,
                bytes.as_ptr() as u64,
                bytes.len() as u64,
            )?;
            if wrote != bytes.len() as u64 {
                return Err(syscall::SysError::from_raw(syscall::EIO as i64));
            }
        }
        Ok(())
    }

    pub fn yield_now() {
        let _ = syscall::call0(syscall::SyscallNumber::ThreadYield);
    }

    pub fn process_exit(code: u64) -> ! {
        let _ = syscall::raw_syscall1(syscall::SyscallNumber::ProcessExit, code);
        loop {
            core::hint::spin_loop();
        }
    }
}

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
        super::runtime_support::write_all(fd, bytes)
    }

    pub fn stdout(bytes: &[u8]) -> SysResult<()> {
        write(STDOUT, bytes)
    }

    pub fn stderr(bytes: &[u8]) -> SysResult<()> {
        write(STDERR, bytes)
    }
}

pub mod logger {
    #[cfg(feature = "runtime")]
    use super::runtime;
    use super::{Write, alloc, ipc, syscall};
    use core::fmt;
    use core::sync::atomic::{AtomicU64, Ordering};

    static LOGGER_ENDPOINT: AtomicU64 = AtomicU64::new(0);

    /// Installs the POSIX endpoint attached to an early-boot logger request.
    pub const INSTALL_POSIX_ENDPOINT_OPCODE: u32 = 0x4c50_5850;

    #[cfg(any(feature = "runtime", feature = "std"))]
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

    #[cfg(feature = "runtime")]
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

    #[cfg(feature = "runtime")]
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

    #[cfg(feature = "std")]
    pub fn init_from_env() -> Option<u64> {
        let mut last_numeric = None;
        for argument in std::env::args() {
            let bytes = argument.as_bytes();
            crate::service_ready::capture_bootstrap_arg(bytes);
            if let Some(value) = parse_decimal_u64(bytes) {
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
            if !cfg!(debug_assertions) {
                return Ok(());
            }
            let mut buf = alloc::string::String::new();
            buf.write_fmt(args)
                .map_err(|_| syscall::SysError::from_raw(syscall::EINVAL as i64))?;
            let _ = ipc::send(endpoint, buf.as_bytes());
            Ok(())
        } else {
            super::write_fmt(super::io::STDOUT, args)
        }
    }

    /// Writes only to logger.service. Unlike `write_fmt`, this never falls back
    /// to the process stdout, so service diagnostics cannot corrupt an
    /// interactive terminal when logger initialization is missing or delayed.
    pub fn write_log_fmt(args: fmt::Arguments<'_>) -> syscall::SysResult<()> {
        if !cfg!(debug_assertions) {
            return Ok(());
        }
        write_status_fmt(args)
    }

    /// Records explicit lifecycle/failure status in Release as well as Debug.
    /// Never writes to stdout or the framebuffer; delivery errors reach the caller.
    pub fn write_status_fmt(args: fmt::Arguments<'_>) -> syscall::SysResult<()> {
        let endpoint =
            endpoint().ok_or_else(|| syscall::SysError::from_raw(syscall::ENOENT as i64))?;
        let mut buf = alloc::string::String::new();
        buf.write_fmt(args)
            .map_err(|_| syscall::SysError::from_raw(syscall::EINVAL as i64))?;
        ipc::send(endpoint, buf.as_bytes()).map(|_| ())
    }

    /// Tells logger.service that boot-critical startup is complete and queued
    /// records may be persisted. The empty-text control byte cannot be emitted
    /// by the formatting helpers above.
    pub fn flush_pending() -> syscall::SysResult<()> {
        let endpoint =
            endpoint().ok_or_else(|| syscall::SysError::from_raw(syscall::ENOENT as i64))?;
        ipc::send(endpoint, &[0]).map(|_| ())
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

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {{
        let _ = $crate::logger::write_log_fmt(format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! logln {
    () => {{
        let _ = $crate::logger::write_log_fmt(format_args!("\n"));
    }};
    ($($arg:tt)*) => {{
        let _ = $crate::logger::write_log_fmt(format_args!("{}\n", format_args!($($arg)*)));
    }};
}

pub mod device {
    use super::syscall::{self, SysResult};
    pub use mnu_abi::{DeviceControlRequest, DeviceControlResponse};

    pub fn control(
        authority: &str,
        request: DeviceControlRequest,
    ) -> SysResult<DeviceControlResponse> {
        let mut response = DeviceControlResponse::default();
        syscall::call4(
            syscall::SyscallNumber::DeviceControl,
            &request as *const _ as u64,
            &mut response as *mut _ as u64,
            authority.as_ptr() as u64,
            authority.len() as u64,
        )?;
        Ok(response)
    }
}

pub mod thread {
    use super::syscall::{self, SysResult};

    pub fn create(context: &syscall::ThreadCreateContext) -> SysResult<u64> {
        syscall::call2(
            syscall::SyscallNumber::ThreadCreate,
            context as *const syscall::ThreadCreateContext as u64,
            core::mem::size_of::<syscall::ThreadCreateContext>() as u64,
        )
    }

    pub fn install_upcall(config: &syscall::ThreadUpcallConfig) -> SysResult<()> {
        syscall::call2(
            syscall::SyscallNumber::ThreadUpcallInstall,
            config as *const syscall::ThreadUpcallConfig as u64,
            core::mem::size_of::<syscall::ThreadUpcallConfig>() as u64,
        )
        .map(|_| ())
    }

    pub fn create_interrupt_handle() -> SysResult<u32> {
        syscall::call0(syscall::SyscallNumber::ThreadHandleCreate)
            .and_then(crate::handle_result::decode)
    }

    pub fn interrupt(handle: u32, payload: u64) -> SysResult<()> {
        syscall::call2(
            syscall::SyscallNumber::ThreadInterrupt,
            u64::from(handle),
            payload,
        )
        .map(|_| ())
    }

    pub fn handle_status(handle: u32) -> SysResult<syscall::ThreadStatus> {
        let mut status = syscall::ThreadStatus::default();
        syscall::call2(
            syscall::SyscallNumber::ThreadHandleStatus,
            u64::from(handle),
            &mut status as *mut syscall::ThreadStatus as u64,
        )?;
        Ok(status)
    }

    pub fn return_from_upcall(token: u64) -> SysResult<()> {
        syscall::call1(syscall::SyscallNumber::ThreadUpcallReturn, token).map(|_| ())
    }

    pub fn yield_now() {
        super::runtime_support::yield_now();
    }

    /// Waits on native handles only while the caller's guard word still equals
    /// its expected value. A changed guard returns native NotReady, not a signal
    /// policy result. See HandleWaitGuard for the notification requirement.
    pub fn wait_many_guarded(
        items: &mut [syscall::HandleWaitItem],
        deadline_nanoseconds: u64,
        guard: &syscall::HandleWaitGuard,
    ) -> SysResult<usize> {
        if items.len() > syscall::HANDLE_WAIT_MANY_MAX_ITEMS {
            return Err(syscall::SysError::from_raw(
                syscall::NativeError::InvalidArgument.into_raw() as i64,
            ));
        }
        let index = syscall::call4(
            syscall::SyscallNumber::HandleWaitManyGuarded,
            items.as_mut_ptr() as u64,
            items.len() as u64,
            deadline_nanoseconds,
            (guard as *const syscall::HandleWaitGuard) as u64,
        )?;
        usize::try_from(index)
            .ok()
            .filter(|index| *index < items.len())
            .ok_or_else(|| {
                syscall::SysError::from_raw(syscall::NativeError::BackingFailure.into_raw() as i64)
            })
    }

    pub fn exit(code: u64) -> ! {
        let _ = syscall::raw_syscall1(syscall::SyscallNumber::ThreadExit, code);
        loop {
            core::hint::spin_loop();
        }
    }

    pub fn sleep_milliseconds(milliseconds: u64) -> SysResult<()> {
        syscall::call1(syscall::SyscallNumber::Sleep, milliseconds).map(|_| ())
    }
}

pub mod process {
    use super::syscall::{self, SysResult};
    use alloc::vec;
    use alloc::vec::Vec;

    pub use mnu_abi::{PROCESS_STATE_EXITED, PROCESS_STATE_RUNNING};

    pub const RECORD_SIZE: usize = syscall::PROCESS_INFO_RECORD_SIZE;

    /// Creates an authorized process in a scheduling-suspended state. The
    /// returned Handle retains exit status even after execution resources are
    /// reclaimed. Register policy/monitoring before calling resume_handle.
    pub fn create_stopped(image: u32, metadata: &[u8]) -> SysResult<u32> {
        mnu_abi::process_create::decode(metadata)
            .map_err(|_| syscall::SysError::from_raw(syscall::EINVAL as i64))?;
        let raw = syscall::call3(
            syscall::SyscallNumber::ProcessCreate,
            image as u64,
            metadata.as_ptr() as u64,
            metadata.len() as u64,
        )?;
        crate::handle_result::decode(raw)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Record {
        pub pid: u64,
        pub state: u64,
        pub cpu_ticks: u64,
        pub memory_bytes: u64,
        pub thread_count: u64,
    }

    pub fn find_by_name(name: &str) -> SysResult<u64> {
        let bytes = name.as_bytes();
        syscall::call2(
            syscall::SyscallNumber::FindProcessByName,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
        )
    }

    pub fn thread_security_context(thread_id: u64) -> SysResult<syscall::ThreadSecurityContext> {
        let mut context = syscall::ThreadSecurityContext::default();
        syscall::call3(
            syscall::SyscallNumber::GetThreadSecurityContext,
            thread_id,
            (&mut context as *mut syscall::ThreadSecurityContext) as u64,
            core::mem::size_of::<syscall::ThreadSecurityContext>() as u64,
        )?;
        Ok(context)
    }

    pub fn current_thread_id() -> SysResult<u64> {
        current_execution_identity().map(|identity| identity.thread_id)
    }

    /// Identifies only this caller, without kernel UID/GID or package policy.
    pub fn current_execution_identity() -> SysResult<syscall::ExecutionIdentity> {
        syscall::execution::identity()
    }

    pub fn open_handle_for_endpoint(endpoint: u64, rights: u64) -> SysResult<u32> {
        syscall::call2(syscall::SyscallNumber::ProcessHandleOpen, endpoint, rights)
            .and_then(crate::handle_result::decode)
    }

    pub fn open_handle_for_process_id(process_id: u64, rights: u64) -> SysResult<u32> {
        syscall::call2(
            syscall::SyscallNumber::ProcessHandleOpenById,
            process_id,
            rights,
        )
        .and_then(crate::handle_result::decode)
    }


    /// Captures a detached VM image. Closing its final Handle releases it;
    /// this does not create a process or copy native execution authority.
    pub fn clone_address_space() -> SysResult<u32> {
        syscall::call0(syscall::SyscallNumber::AddressSpaceClone)
            .and_then(crate::handle_result::decode)
    }

    pub fn resume_handle(handle: u32) -> SysResult<()> {
        syscall::call1(
            syscall::SyscallNumber::ProcessHandleResume,
            u64::from(handle),
        )
        .map(|_| ())
    }

    /// Suspends the process referenced by an authorized native handle.
    /// Policy layers assign their own meaning to this scheduling state.
    pub fn suspend_handle(handle: u32) -> SysResult<()> {
        syscall::call1(
            syscall::SyscallNumber::ProcessHandleSuspend,
            u64::from(handle),
        )
        .map(|_| ())
    }

    /// Suspends the current native process until an authorized process-handle
    /// holder resumes it. Policy layers assign their own meaning to this state.
    pub fn suspend_current() -> SysResult<()> {
        syscall::call0(syscall::SyscallNumber::ProcessSuspendCurrent).map(|_| ())
    }

    pub fn terminate_handle(handle: u32, exit_code: u64) -> SysResult<()> {
        syscall::call2(
            syscall::SyscallNumber::ProcessHandleTerminate,
            u64::from(handle),
            exit_code,
        )
        .map(|_| ())
    }

    pub fn handle_status(handle: u32) -> SysResult<syscall::ProcessStatus> {
        let mut status = syscall::ProcessStatus::default();
        syscall::call2(
            syscall::SyscallNumber::ProcessHandleStatus,
            u64::from(handle),
            (&mut status as *mut syscall::ProcessStatus) as u64,
        )?;
        Ok(status)
    }

    /// Samples the CPU execution domains of the caller (None) or of a native
    /// Process Handle granting WAIT. Process identifiers are never accepted.
    pub fn execution_usage(handle: Option<u32>) -> SysResult<syscall::ProcessExecutionUsage> {
        syscall::execution::usage(handle)
    }

    pub fn wait_handle(
        handle: u32,
        deadline_nanoseconds: u64,
    ) -> SysResult<syscall::ProcessStatus> {
        let mut status = syscall::ProcessStatus::default();
        syscall::call3(
            syscall::SyscallNumber::ProcessHandleWait,
            u64::from(handle),
            deadline_nanoseconds,
            (&mut status as *mut syscall::ProcessStatus) as u64,
        )?;
        Ok(status)
    }

    /// Waits for one native signal across process-local object handles and
    /// returns the index of the first ready item.
    pub fn wait_many(
        items: &mut [syscall::HandleWaitItem],
        deadline_nanoseconds: u64,
    ) -> SysResult<usize> {
        if items.len() > syscall::HANDLE_WAIT_MANY_MAX_ITEMS {
            return Err(syscall::SysError::from_raw(
                syscall::NativeError::InvalidArgument.into_raw() as i64,
            ));
        }
        let index = syscall::call3(
            syscall::SyscallNumber::HandleWaitMany,
            items.as_mut_ptr() as u64,
            items.len() as u64,
            deadline_nanoseconds,
        )?;
        usize::try_from(index)
            .ok()
            .filter(|index| *index < items.len())
            .ok_or_else(|| {
                syscall::SysError::from_raw(syscall::NativeError::BackingFailure.into_raw() as i64)
            })
    }

    pub fn exit(code: u64) -> ! {
        super::runtime_support::process_exit(code)
    }

    pub fn list(max_records: usize) -> SysResult<Vec<Record>> {
        let mut bytes = vec![0u8; RECORD_SIZE.saturating_mul(max_records)];
        let count = syscall::call2(
            syscall::SyscallNumber::ListProcesses,
            bytes.as_mut_ptr() as u64,
            bytes.len() as u64,
        )? as usize;
        let mut records = Vec::with_capacity(count.min(max_records));
        for record in bytes.chunks_exact(RECORD_SIZE).take(count.min(max_records)) {
            records.push(Record {
                pid: read_u64(record, 0),
                state: read_u64(record, 16),
                cpu_ticks: read_u64(record, 24),
                memory_bytes: read_u64(record, 32),
                thread_count: read_u64(record, 40),
            });
        }
        Ok(records)
    }

    fn read_u64(bytes: &[u8], offset: usize) -> u64 {
        u64::from_ne_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ])
    }
}

pub mod ipc {
    use super::syscall::{self, SysResult};

    pub use mnu_abi::{IpcObjectHandle, IpcObjectHandles};

    pub fn create() -> SysResult<u64> {
        syscall::call2(syscall::SyscallNumber::IpcCreate, 0, 0)
    }

    /// Creates an IPC endpoint represented by a process-local object handle.
    pub fn create_handle() -> SysResult<u32> {
        let raw = syscall::call2(syscall::SyscallNumber::IpcCreateHandle, 0, 0)?;
        crate::handle_result::decode(raw)
    }

    pub fn send(endpoint: u64, bytes: &[u8]) -> SysResult<u64> {
        syscall::call3(
            syscall::SyscallNumber::IpcSend,
            endpoint,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
        )
    }

    /// Sends a message with rights-restricted process-local object handles.
    pub fn send_object_handles(
        endpoint: u64,
        bytes: &[u8],
        handles: &IpcObjectHandles,
    ) -> SysResult<u64> {
        syscall::call4(
            syscall::SyscallNumber::IpcSendObjectHandles,
            endpoint,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            handles as *const IpcObjectHandles as u64,
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

    /// Waits for a message and installs attached object handles locally.
    pub fn wait_object_handles(
        endpoint: u64,
        buf: &mut [u8],
        handles: &mut IpcObjectHandles,
    ) -> SysResult<u64> {
        *handles = IpcObjectHandles::default();
        syscall::call4(
            syscall::SyscallNumber::IpcRecvObjectHandles,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            handles as *mut IpcObjectHandles as u64,
            endpoint,
        )
    }

    /// Tries to receive a message with object handles without blocking.
    pub fn try_wait_object_handles(
        buf: &mut [u8],
        handles: &mut IpcObjectHandles,
    ) -> SysResult<u64> {
        wait_object_handles(0, buf, handles)
    }

    pub fn endpoint_alive(endpoint: u64) -> bool {
        syscall::call1(syscall::SyscallNumber::IpcEndpointAlive, endpoint).is_ok()
    }

    pub fn endpoint_owner_process(endpoint: u64) -> SysResult<u64> {
        syscall::call1(syscall::SyscallNumber::IpcEndpointOwner, endpoint)
    }

    pub fn endpoint_execution_identity(endpoint: u64) -> SysResult<syscall::ExecutionIdentity> {
        syscall::execution::endpoint_identity(endpoint)
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

    /// Performs a synchronous call with generic object handles in both
    /// directions. `handles` initially describes request attachments and is
    /// replaced with the receiver-local handles attached to the reply.
    pub fn call_object_handles(
        endpoint: u32,
        request: &[u8],
        reply: &mut [u8],
        handles: &mut IpcObjectHandles,
    ) -> SysResult<u64> {
        syscall::call6(
            syscall::SyscallNumber::IpcCallObjectHandles,
            endpoint as u64,
            request.as_ptr() as u64,
            request.len() as u64,
            reply.as_mut_ptr() as u64,
            reply.len() as u64,
            handles as *mut IpcObjectHandles as u64,
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

    /// Replies to a synchronous call with rights-restricted generic object
    /// handles attached to the response.
    pub fn reply_object_handles(
        sender_handle: u64,
        bytes: &[u8],
        handles: &IpcObjectHandles,
    ) -> SysResult<u64> {
        syscall::call4(
            syscall::SyscallNumber::IpcReplyObjectHandles,
            sender_handle,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            handles as *const IpcObjectHandles as u64,
        )
    }

}

/// Operations on process-local kernel object handles.
pub mod handle {
    use super::syscall::{self, SysResult};

    pub type Handle = u32;

    pub use mnu_abi::{
        HANDLE_RIGHT_ALL, HANDLE_RIGHT_CONTROL, HANDLE_RIGHT_DUPLICATE, HANDLE_RIGHT_MAP,
        HANDLE_RIGHT_READ, HANDLE_RIGHT_RECEIVE, HANDLE_RIGHT_SEEK, HANDLE_RIGHT_SEND,
        HANDLE_RIGHT_SIGNAL, HANDLE_RIGHT_TRANSFER, HANDLE_RIGHT_WAIT, HANDLE_RIGHT_WRITE,
        HANDLE_SEEK_CURRENT, HANDLE_SEEK_END, HANDLE_SEEK_START,
    };

    fn decode(raw: u64) -> SysResult<Handle> {
        crate::handle_result::decode(raw)
    }

    pub fn close(handle: Handle) -> SysResult<()> {
        syscall::call1(syscall::SyscallNumber::HandleClose, handle as u64).map(|_| ())
    }

    /// Duplicates a handle while monotonically reducing its rights.
    pub fn duplicate(handle: Handle, requested_rights: u64) -> SysResult<Handle> {
        decode(syscall::call2(
            syscall::SyscallNumber::HandleDuplicate,
            handle as u64,
            requested_rights,
        )?)
    }

    /// Looks up a handle inherited under an opaque launch-context key.
    pub fn inherited(key: u64) -> SysResult<Handle> {
        decode(syscall::call1(
            syscall::SyscallNumber::LaunchHandleGet,
            key,
        )?)
    }

    /// Associates an already-owned handle with an opaque process-context key.
    /// This replaces any previous association without changing handle rights.
    pub fn set_context_handle(key: u64, handle: Handle) -> SysResult<()> {
        syscall::call2(
            syscall::SyscallNumber::ContextHandleSet,
            key,
            handle as u64,
        )
        .map(|_| ())
    }

    pub fn remove_context_handle(key: u64) -> SysResult<()> {
        syscall::call1(syscall::SyscallNumber::ContextHandleRemove, key).map(|_| ())
    }

    pub fn set_context_value(key: u64, value: u64) -> SysResult<()> {
        syscall::call2(syscall::SyscallNumber::ContextValueSet, key, value).map(|_| ())
    }

    pub fn remove_context_value(key: u64) -> SysResult<()> {
        syscall::call1(syscall::SyscallNumber::ContextValueRemove, key).map(|_| ())
    }

    pub fn rights(handle: Handle) -> SysResult<u64> {
        syscall::call1(syscall::SyscallNumber::HandleRightsGet, handle as u64)
    }

    /// Reads metadata for all currently owned Handles, without acquiring any
    /// reference. An empty slice queries the count. A too-small slice returns
    /// native LimitExceeded rather than a truncated list. Later transfers
    /// revalidate rights; the count query does not reserve table entries.
    pub fn table_read(output: &mut [syscall::HandleInfo]) -> SysResult<usize> {
        syscall::call2(
            syscall::SyscallNumber::HandleTableRead,
            if output.is_empty() {
                0
            } else {
                output.as_mut_ptr() as u64
            },
            output.len() as u64,
        )
        .map(|count| count as usize)
    }

    /// Returns whether two process-local handles refer to the same kernel
    /// object without exposing a reusable global object identifier.
    pub fn same_object(left: Handle, right: Handle) -> SysResult<bool> {
        syscall::call2(
            syscall::SyscallNumber::HandleSameObject,
            left as u64,
            right as u64,
        )
        .map(|same| same != 0)
    }

    /// Retrieves an opaque value inherited through the process LaunchContext.
    pub fn inherited_value(key: u64) -> SysResult<u64> {
        let mut value = 0u64;
        syscall::call2(
            syscall::SyscallNumber::LaunchValueGet,
            key,
            (&mut value as *mut u64) as u64,
        )?;
        Ok(value)
    }

    /// Creates a transferable object backed by the caller-supplied provider
    /// endpoint and an opaque provider-owned identifier.
    pub fn create_provider_object(
        endpoint: Handle,
        object_id: u64,
        rights: u64,
    ) -> SysResult<Handle> {
        decode(syscall::call3(
            syscall::SyscallNumber::ProviderObjectCreate,
            endpoint as u64,
            object_id,
            rights,
        )?)
    }

    /// Returns the provider-owned identifier of an attached object. This is
    /// accepted only on the exact endpoint thread that created the object.
    pub fn identify_provider_object(handle: Handle) -> SysResult<u64> {
        syscall::call1(
            syscall::SyscallNumber::ProviderObjectIdentify,
            handle as u64,
        )
    }

    /// Samples all strong references except this query's temporary reference.
    /// Only the exact creating endpoint may query its own opaque object IDs.
    /// Includes in-flight IPC/kernel references, not just process Handles;
    /// the sample is conservative and does not pin or revoke any reference.
    pub fn provider_object_reference_count(object_id: u64) -> SysResult<u64> {
        syscall::call1(syscall::SyscallNumber::ProviderObjectReferenceCount, object_id)
    }

    /// Private ownership of a prepared provider-memory extent update. It is
    /// neither clonable nor transferable. Drop cancels before begin, or
    /// quarantines an unconfirmed in-flight backing after begin.
    pub struct ProviderMemoryUpdate {
        handle: Handle,
    }

    impl ProviderMemoryUpdate {
        /// Call before issuing external mutation. No storage I/O is performed.
        pub fn begin(&mut self) -> SysResult<()> {
            self.operation(mnu_abi::memory_update::BEGIN)
        }

        /// Confirm storage is unchanged, not merely that an I/O error occurred.
        pub fn confirm_unchanged(&mut self) -> SysResult<()> {
            self.operation(mnu_abi::memory_update::UNCHANGED)
        }

        /// Confirm the new extent is authoritative. Once requested, even an
        /// error/drop keeps publication intent for deferred cleanup retry.
        pub fn publish(&mut self) -> SysResult<()> {
            self.operation(mnu_abi::memory_update::PUBLISH)
        }

        fn operation(&mut self, code: u64) -> SysResult<()> {
            syscall::call6(
                syscall::SyscallNumber::HandleControl,
                self.handle as u64,
                code,
                0,
                0,
                0,
                0,
            )
            .map(|_| ())
        }
    }

    impl Drop for ProviderMemoryUpdate {
        fn drop(&mut self) {
            let _ = close(self.handle);
        }
    }

    /// Requires a caller-local RECEIVE endpoint capability, not a consumer's
    /// FileHandle CONTROL. Identity is scoped to that exact provider endpoint.
    pub fn prepare_provider_memory_update(
        endpoint: Handle,
        identity: u64,
        old_length: u64,
        length: u64,
    ) -> SysResult<ProviderMemoryUpdate> {
        let handle = decode(syscall::call5(
            syscall::SyscallNumber::ProviderMemoryUpdateCreate,
            endpoint as u64,
            identity,
            old_length,
            length,
            0,
        )?)?;
        Ok(ProviderMemoryUpdate { handle })
    }

    /// Owned, transferable FIFO position. This grants WAIT only (plus
    /// TRANSFER), not permission to consume it or mutate external storage.
    /// Dropping the final reference cancels the position without VM edits.
    pub struct ProviderMemoryAdmission {
        handle: Handle,
    }

    impl ProviderMemoryAdmission {
        pub fn handle(&self) -> Handle {
            self.handle
        }
        /// Transfer reference ownership to an IPC/Handle owner.
        /// IPC copies references: the sender must close this raw reference
        /// after sending, including when delivery fails.
        pub fn into_handle(self) -> Handle {
            let handle = self.handle;
            core::mem::forget(self);
            handle
        }
        /// Sleeps using generic native readiness, not service RPC or polling.
        /// Upcall/endpoint-death errors are returned to the caller.
        pub fn wait(&self) -> SysResult<()> {
            wait_provider_memory_admission(self.handle)
        }
    }
    impl Drop for ProviderMemoryAdmission {
        fn drop(&mut self) {
            let _ = close(self.handle);
        }
    }

    /// Wait on a borrowed admission reference received by IPC. Ownership
    /// stays with the receiver; readiness does not consume the queue position.
    pub fn wait_provider_memory_admission(handle: Handle) -> SysResult<()> {
        let mut items = [syscall::HandleWaitItem {
            handle,
            interests: mnu_abi::HANDLE_SIGNAL_READABLE | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
            ..Default::default()
        }];
        super::process::wait_many(&mut items, mnu_abi::HANDLE_WAIT_INFINITE)?;
        if items[0].observed & mnu_abi::HANDLE_SIGNAL_READABLE != 0 {
            Ok(())
        } else {
            Err(syscall::SysError::from_raw(syscall::EIO as i64))
        }
    }

    /// Requires the endpoint owner's RECEIVE capability. The identity is
    /// opaque, not a pathname or descriptor. Does not wait or perform I/O.
    pub fn create_provider_memory_admission(
        endpoint: Handle,
        identity: u64,
    ) -> SysResult<ProviderMemoryAdmission> {
        let handle = decode(syscall::call2(
            syscall::SyscallNumber::ProviderMemoryAdmissionCreate,
            endpoint as u64,
            identity,
        )?)?;
        Ok(ProviderMemoryAdmission { handle })
    }

    /// Consume a borrowed queue position using the original endpoint owner's
    /// RECEIVE authority. The opaque ticket must name that exact backing.
    /// Ownership of the Handle reference stays with the caller on all paths.
    /// A failed preparation can consume the position; such a reference then
    /// reports closed. Do not assume a failed call leaves a reusable position.
    pub fn prepare_provider_memory_update_admitted(
        endpoint: Handle,
        identity: u64,
        old_length: u64,
        length: u64,
        admission: Handle,
    ) -> SysResult<ProviderMemoryUpdate> {
        let handle = decode(syscall::call5(
            syscall::SyscallNumber::ProviderMemoryUpdateCreate,
            endpoint as u64,
            identity,
            old_length,
            length,
            admission as u64,
        )?)?;
        Ok(ProviderMemoryUpdate { handle })
    }

    /// Updates generic readiness signals for an object owned by the caller's
    /// provider endpoint.
    pub fn signal_provider_object(object_id: u64, set: u64, clear: u64) -> SysResult<()> {
        syscall::call3(
            syscall::SyscallNumber::ProviderObjectSignal,
            object_id,
            set,
            clear,
        )
        .map(|_| ())
    }

    pub fn read(handle: Handle, buffer: &mut [u8]) -> SysResult<usize> {
        let length = syscall::call3(
            syscall::SyscallNumber::HandleRead,
            handle as u64,
            buffer.as_mut_ptr() as u64,
            buffer.len() as u64,
        )?;
        usize::try_from(length).map_err(|_| syscall::SysError::from_raw(syscall::EOVERFLOW as i64))
    }

    pub fn write(handle: Handle, buffer: &[u8]) -> SysResult<usize> {
        let length = syscall::call3(
            syscall::SyscallNumber::HandleWrite,
            handle as u64,
            buffer.as_ptr() as u64,
            buffer.len() as u64,
        )?;
        usize::try_from(length).map_err(|_| syscall::SysError::from_raw(syscall::EOVERFLOW as i64))
    }

    /// Reads bytes at an explicit offset without changing the object's cursor.
    pub fn read_at(handle: Handle, buffer: &mut [u8], offset: u64) -> SysResult<usize> {
        let length = syscall::call4(
            syscall::SyscallNumber::HandleReadAt,
            handle as u64,
            buffer.as_mut_ptr() as u64,
            buffer.len() as u64,
            offset,
        )?;
        usize::try_from(length).map_err(|_| syscall::SysError::from_raw(syscall::EOVERFLOW as i64))
    }

    /// Writes bytes at an explicit offset without changing the object's cursor.
    pub fn write_at(handle: Handle, buffer: &[u8], offset: u64) -> SysResult<usize> {
        let length = syscall::call4(
            syscall::SyscallNumber::HandleWriteAt,
            handle as u64,
            buffer.as_ptr() as u64,
            buffer.len() as u64,
            offset,
        )?;
        usize::try_from(length).map_err(|_| syscall::SysError::from_raw(syscall::EOVERFLOW as i64))
    }

    /// Sends an opaque bounded control request to an object provider.
    pub fn control(
        handle: Handle,
        control_code: u64,
        input: &[u8],
        output: &mut [u8],
    ) -> SysResult<usize> {
        let length = syscall::call6(
            syscall::SyscallNumber::HandleControl,
            handle as u64,
            control_code,
            input.as_ptr() as u64,
            input.len() as u64,
            output.as_mut_ptr() as u64,
            output.len() as u64,
        )?;
        usize::try_from(length).map_err(|_| syscall::SysError::from_raw(syscall::EOVERFLOW as i64))
    }

    /// Moves the shared cursor of an I/O object using a native seek basis.
    /// Compatibility layers must translate POSIX `SEEK_*` values before
    /// calling this function.
    pub fn seek(handle: Handle, offset: i64, basis: u64) -> SysResult<u64> {
        syscall::call3(
            syscall::SyscallNumber::HandleSeek,
            handle as u64,
            offset as u64,
            basis,
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
    pub use mnu_abi::exec::ExecutionClass;

    pub fn authorize_exec_for_requester(
        requester_tid: u64,
        path: &str,
        identity_nul: &[u8],
        caps_nul: &[u8],
    ) -> SysResult<u64> {
        let path = super::path::CPath::<256>::new(path)?;
        syscall::call5(
            syscall::SyscallNumber::AuthorizeExec,
            requester_tid,
            path.as_ptr(),
            identity_nul.as_ptr() as u64,
            caps_nul.as_ptr() as u64,
            caps_nul.len() as u64,
        )
    }
}

pub mod service_ready;

pub mod time {
    use super::syscall::{self, SysResult};
    use mnu_abi::{ClockId, ClockInstant};

    pub fn ticks() -> SysResult<u64> {
        syscall::call0(syscall::SyscallNumber::TimeNow)
    }

    pub fn utc_seconds() -> SysResult<u64> {
        let mut instant = ClockInstant::default();
        syscall::call2(
            syscall::SyscallNumber::ClockRead,
            ClockId::Realtime as u64,
            (&mut instant as *mut ClockInstant) as u64,
        )?;
        if instant.nanoseconds >= 1_000_000_000 || instant.reserved != 0 {
            return Err(syscall::NativeError::BackingFailure.into_raw().into());
        }
        Ok(instant.seconds)
    }

    pub fn monotonic_milliseconds() -> SysResult<u64> {
        let mut instant = ClockInstant::default();
        syscall::call2(
            syscall::SyscallNumber::ClockRead,
            ClockId::Monotonic as u64,
            (&mut instant as *mut ClockInstant) as u64,
        )?;
        if instant.nanoseconds >= 1_000_000_000 || instant.reserved != 0 {
            return Err(syscall::NativeError::BackingFailure.into_raw().into());
        }
        instant
            .seconds
            .checked_mul(1_000)
            .and_then(|milliseconds| {
                milliseconds.checked_add(u64::from(instant.nanoseconds) / 1_000_000)
            })
            .ok_or_else(|| syscall::NativeError::LimitExceeded.into_raw().into())
    }

    pub fn monotonic_nanoseconds() -> SysResult<u64> {
        let mut instant = ClockInstant::default();
        syscall::call2(
            syscall::SyscallNumber::ClockRead,
            ClockId::Monotonic as u64,
            (&mut instant as *mut ClockInstant) as u64,
        )?;
        if instant.nanoseconds >= 1_000_000_000 || instant.reserved != 0 {
            return Err(syscall::NativeError::BackingFailure.into_raw().into());
        }
        instant
            .seconds
            .checked_mul(1_000_000_000)
            .and_then(|seconds| seconds.checked_add(u64::from(instant.nanoseconds)))
            .ok_or_else(|| syscall::NativeError::LimitExceeded.into_raw().into())
    }
}

pub mod synchronization {
    use super::syscall::{self, SysResult};
    pub use mnu_abi::AddressWaitResult;

    /// Waits while the value at `address` equals `expected`.
    ///
    /// `value_size` must be 1, 2, 4, or 8 and `address` must be naturally
    /// aligned. The deadline is an absolute native monotonic-clock value.
    ///
    /// # Safety
    ///
    /// The caller must keep `address` mapped and valid for atomic access for
    /// the duration of this call.
    pub unsafe fn wait_on_address(
        address: *const u8,
        expected: u64,
        value_size: usize,
        deadline_nanoseconds: u64,
    ) -> SysResult<AddressWaitResult> {
        let raw = syscall::call4(
            syscall::SyscallNumber::WaitOnAddress,
            address as u64,
            expected,
            value_size as u64,
            deadline_nanoseconds,
        )?;
        AddressWaitResult::from_raw(raw)
            .ok_or_else(|| syscall::NativeError::BackingFailure.into_raw().into())
    }

    /// Wakes up to `maximum_count` waiters for `address`.
    ///
    /// # Safety
    ///
    /// `address` must refer to mapped memory that identifies the same atomic
    /// object supplied to `wait_on_address`.
    pub unsafe fn wake_address(address: *const u8, maximum_count: usize) -> SysResult<usize> {
        let count = syscall::call2(
            syscall::SyscallNumber::WakeAddress,
            address as u64,
            maximum_count as u64,
        )?;
        if count > maximum_count as u64 {
            return Err(syscall::NativeError::BackingFailure.into_raw().into());
        }
        usize::try_from(count)
            .map_err(|_| syscall::NativeError::LimitExceeded.into_raw().into())
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
            return Err(syscall::NativeError::BackingFailure.into_raw().into());
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

    /// Creates page-aligned, zero-filled backing transferable through IPC.
    pub fn create_object(len: u64) -> SysResult<u64> {
        syscall::call2(syscall::SyscallNumber::MemoryObjectCreate, len, 0)
    }

    pub fn object_length(handle: u64) -> SysResult<u64> {
        syscall::call1(syscall::SyscallNumber::MemoryObjectLength, handle)
    }

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

    pub fn map(
        addr: u64,
        len: u64,
        access: u64,
        options: u64,
        backing_handle: u64,
    ) -> SysResult<u64> {
        map_at_offset(addr, len, access, options, backing_handle, 0)
    }

    pub fn map_at_offset(
        addr: u64,
        len: u64,
        access: u64,
        options: u64,
        backing_handle: u64,
        offset: u64,
    ) -> SysResult<u64> {
        syscall::call6(
            syscall::SyscallNumber::MemoryMap,
            addr,
            len,
            access,
            options,
            backing_handle,
            offset,
        )
    }

    pub fn munmap(addr: u64, len: u64) -> SysResult<u64> {
        syscall::call2(syscall::SyscallNumber::MemoryUnmap, addr, len)
    }

    /// Changes permissions using mnu-native `MEMORY_ACCESS_*` flags.
    pub fn protect(addr: u64, len: u64, access: u64) -> SysResult<u64> {
        syscall::call3(syscall::SyscallNumber::MemoryProtect, addr, len, access)
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

    pub fn present_framebuffer(
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        pixels: &[u8],
    ) -> SysResult<u64> {
        let position = u64::from(x) | (u64::from(y) << 32);
        let size = u64::from(width) | (u64::from(height) << 32);
        syscall::call4(
            syscall::SyscallNumber::PresentFramebuffer,
            position,
            size,
            pixels.as_ptr() as u64,
            pixels.len() as u64,
        )
    }

    pub fn framebuffer_transfer_limit() -> SysResult<usize> {
        let limit = syscall::call0(syscall::SyscallNumber::FramebufferTransferLimit)?;
        usize::try_from(limit).map_err(|_| syscall::SysError::from_raw(syscall::ERANGE as i64))
    }

    pub fn commit_framebuffer(x: u32, y: u32, width: u32, height: u32) -> SysResult<u64> {
        let position = u64::from(x) | (u64::from(y) << 32);
        let size = u64::from(width) | (u64::from(height) << 32);
        syscall::call2(syscall::SyscallNumber::CommitFramebuffer, position, size)
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

pub mod storage {
    use super::syscall::{self, SysResult};

    pub use mnu_abi::{
        STORAGE_CONTROL_CREATE_PARTITION, STORAGE_CONTROL_DELETE_PARTITION,
        STORAGE_CONTROL_INSPECT, STORAGE_CONTROL_INSTALL_PARTITION, STORAGE_CONTROL_LIST_DEVICE,
        STORAGE_QUERY_DISK, STORAGE_QUERY_PARTITION_GUIDS, STORAGE_QUERY_PARTITION_RANGE,
        STORAGE_STATUS_END, STORAGE_STATUS_OK,
    };
    pub use mnu_abi::{StorageControlRequest, StorageControlResponse};

    pub fn control(request: StorageControlRequest) -> SysResult<StorageControlResponse> {
        let mut response = StorageControlResponse::default();
        syscall::call2(
            syscall::SyscallNumber::StorageControl,
            (&request as *const StorageControlRequest) as u64,
            (&mut response as *mut StorageControlResponse) as u64,
        )?;
        Ok(response)
    }

    pub fn block_read(disk_id: u32, lba: u64, destination: &mut [u8]) -> SysResult<u64> {
        syscall::call4(
            syscall::SyscallNumber::BlockRead,
            u64::from(disk_id),
            lba,
            destination.as_mut_ptr() as u64,
            destination.len() as u64,
        )
    }

    pub fn block_write(disk_id: u32, lba: u64, source: &[u8]) -> SysResult<u64> {
        syscall::call4(
            syscall::SyscallNumber::BlockWrite,
            u64::from(disk_id),
            lba,
            source.as_ptr() as u64,
            source.len() as u64,
        )
    }

    pub fn block_flush(disk_id: u32) -> SysResult<u64> {
        syscall::call1(syscall::SyscallNumber::BlockFlush, u64::from(disk_id))
    }
}

pub mod boot {
    use super::syscall::{self, SysResult};

    pub use mnu_abi::boot::{BOOT_SYSTEM_SLOT_A, BOOT_SYSTEM_SLOT_B, BOOT_SYSTEM_SLOT_LEGACY};

    /// Returns 0 for legacy images, 1 for system A, or 2 for system B.
    pub fn system_slot() -> SysResult<u64> {
        syscall::call0(syscall::SyscallNumber::BootSystemSlot)
    }

    pub fn esp_guid() -> SysResult<[u8; 16]> {
        let mut guid = [0u8; 16];
        syscall::call2(
            syscall::SyscallNumber::BootEspGuid,
            guid.as_mut_ptr() as u64,
            guid.len() as u64,
        )?;
        Ok(guid)
    }
}

pub mod performance {
    use super::syscall::{self, SysResult};

    pub use mnu_abi::performance::{KernelPerformanceSnapshot, LatencyMetric, VfsActivitySnapshot};

    pub fn snapshot() -> SysResult<KernelPerformanceSnapshot> {
        let mut snapshot = KernelPerformanceSnapshot::default();
        syscall::call2(
            syscall::SyscallNumber::PerformanceSnapshot,
            (&mut snapshot as *mut KernelPerformanceSnapshot) as u64,
            core::mem::size_of::<KernelPerformanceSnapshot>() as u64,
        )?;
        Ok(snapshot)
    }
}

pub mod capability {
    mod prepared_image;
    pub use prepared_image::{PreparedExecutionImage, prepare_execution_image};
    use super::syscall::{self, SysResult};
    pub use mochios_capability_protocol::{
        AUTHORIZE_EXEC_OPCODE, CAPABILITY_DECISION_OPCODE, CAPABILITY_PERSISTENT_QUERY_OPCODE,
        CAPABILITY_PROMPT_OPCODE, CAPABILITY_RESPONSE_OPCODE, CapabilityClass, CapabilityDecision,
        CapabilityDecisionRequest, CapabilityRequest, ExecutableIdentity,
        INSTALL_POSIX_ENDPOINT_OPCODE, MAX_CAPABILITY_NAME_LEN, MAX_DECISION_PAYLOAD_SIZE,
        MAX_EXECUTABLE_PATH_LEN, MAX_PAYLOAD_SIZE, MAX_REASON_LEN, MAX_RESOURCE_PATH_LEN,
        PACKAGE_INDEX_CHANGED_OPCODE, PROTOCOL_VERSION, ProtocolError, RESOLVE_CAPABILITIES_OPCODE,
        RESOLVE_CAPABILITIES_REPLY_STATUS_LEN, RESOLVE_CAPABILITIES_REQUEST_PREFIX_LEN,
        RESOLVE_EXECUTION_SECURITY_OPCODE, ResolveCapabilitiesReply, ResolveExecutionSecurityReply,
        PREPARE_EXECUTION_IMAGE_OPCODE, encode_prepare_execution_image_request,
        decode_prepare_execution_image_request, decode_prepare_execution_image_reply,
        ResourceDescriptor, decode_authorize_exec_request, decode_decision_request, decode_request,
        decode_resolve_capabilities_reply, decode_resolve_capabilities_request,
        decode_resolve_execution_security_reply, decode_resolve_execution_security_request,
        encode_authorize_exec_request, encode_decision_request, encode_request,
        encode_resolve_capabilities_reply, encode_resolve_capabilities_request,
        encode_resolve_execution_security_reply, encode_resolve_execution_security_request,
    };

    pub fn capability_from_string(name: &str) -> CapabilityClass {
        match mnu_abi::capability::metadata(name).map(|metadata| metadata.classification) {
            Some(mnu_abi::capability::CapabilityClassification::UserGrantable) => {
                CapabilityClass::UserGrantable
            }
            Some(mnu_abi::capability::CapabilityClassification::Privileged) => {
                CapabilityClass::Privileged
            }
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
mod native_mpkg_reader;
