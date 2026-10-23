#![no_std]
#![feature(linkage)]

mod child_cleanup;
mod child_startup;
mod fd_lease;
mod fd_creation;
use fd_creation::PendingFdReservation;
mod file_handle_import;
mod callback_resources;
mod file_mutation;
mod file_metadata;
mod file_time;
mod stat_output;
mod terminal_memory;
mod terminal_name;
mod terminal_attributes;
mod terminal_read;
mod file_kind;
mod vector_memory;
mod socket_memory;
mod socket_receive_address;
mod time_memory;
mod interval_timer;
mod process_timer;
mod multiplex_memory;
#[cfg(feature = "trace-io")]
mod io_trace;
mod resource_limit_memory;
mod signal_memory;
mod signal_info;
mod signal_action;
mod directory_io;
mod path_io;
mod user_copy;
mod exec_inputs;
mod exec_search;
mod exec_interpreter;
mod string_configuration;
mod spawn_output;
mod spawn_attributes;
mod spawn_file_actions;
mod spawn_resources;
mod wait_output;
mod wait_id;
mod io_resources;
mod cpu_sleep;
mod mapping_io;
mod mapping_backing;
mod memory_refresh;
mod object_reply;
mod shared_memory_namespace;
mod current_directory;
mod canonical_path;
mod pipe;
mod pty_creation;
mod terminal_lock;
mod terminal_grant;
mod pty_master;
mod vector_metadata;
use vector_metadata::VectorMetadata;
mod image_startup;
mod handle_capture;
mod fork_policy;
mod resource_policy;
mod address_space;
mod heap;
use heap::HeapState;
mod atfork;
mod libc_lock;
mod thread_lifecycle;
mod thread_reference;
mod thread_clock;
mod process_clock;
mod thread_stack;
mod pthread_attr;
mod credentials;
mod groups;
mod groups_memory;
mod pthread_mutex;
mod pthread_cond;
mod pthread_once;
mod pthread_rwlock;
mod pthread_barrier;
mod pthread_spin;
mod pthread_time;
mod semaphore;
mod named_semaphore;
mod shared_memory;
mod fd_options;
mod socket;
mod socket_record;
mod socket_message;
mod stdio_cancellation;
mod thread_cleanup;
mod thread_lookup;
mod fault_signal;
mod signal_delivery;
mod signal_stack;
mod signal_preparation;
mod signal_scope;
mod signal_jump;
mod process_accounting;
use signal_preparation::Preparation;

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_void};
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::ptr;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

use mochi_user_syscall as syscall;
use mochios_capability_protocol::{
    AUTHORIZE_EXEC_OPCODE, CAPABILITY_PERSISTENT_QUERY_OPCODE, CAPABILITY_PROMPT_OPCODE,
    CapabilityClass, CapabilityDecision, CapabilityExecutableIdentity, CapabilityPromptRequest,
    CapabilityResourceDescriptor, MAX_CAPABILITY_NAME_LEN, MAX_EXECUTABLE_PATH_LEN, MAX_REASON_LEN,
};
use mochios_filesystem_protocol as filesystem_protocol;
use mochios_posix_client::fd::{
    Entry as PosixFdEntry, FdError, FdReservation, FdTable, HandleOps, LaunchContextOps,
    LaunchFdDescription, LaunchFdError, plan_launch_context, restore_launch_context,
};
use mochios_posix_client::newlib_errno::{
    E2BIG, EACCES, EAGAIN, EBADF, EBUSY, ECHILD, EDEADLK, EEXIST, EFAULT, EFBIG, EINTR, EINVAL,
    EIO, EISDIR, EMFILE, ENAMETOOLONG, ENOENT, ENOEXEC, ENOMEM, ENOSYS, ENOTDIR, ENOTSUP,
    ENOTTY, EOVERFLOW, EPERM, EPIPE, ERANGE, ESPIPE, ESRCH,
};
use mochios_posix_client::signal_context::{SigInfo, UContext};
use mochios_posix_client::{
    Client as PosixClient, ClientError as PosixClientError, StatAtBase, SyscallEndpointTransport,
};
use mochios_posix_client::{AccessAtBase, ObjectHandleAttachment, OpenAtBase};
use mochios_posix_protocol as posix_protocol;
use mochios_posix_protocol::{FileStatus as PosixFileStatus, STAT_NOFOLLOW};

const PAGE_SIZE: usize = 4096;
const MAX_FDS: usize = 64;
const NATIVE_READ_WRITE: u64 = mnu_abi::MEMORY_ACCESS_READ | mnu_abi::MEMORY_ACCESS_WRITE;
const MAP_FAILED: *mut c_void = (-1isize) as *mut c_void;
const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 2;
const SC_OPEN_MAX: c_int = 4;
const SC_PAGESIZE: c_int = 8;
const SC_NPROCESSORS_CONF: c_int = 9;
const SC_NPROCESSORS_ONLN: c_int = 10;
const SC_THREAD_STACK_MIN: c_int = 39;
const SC_GETPW_R_SIZE_MAX: c_int = 51;
const SC_HOST_NAME_MAX: c_int = 65;
const O_CLOEXEC: c_int = 0x40000;
const O_NONBLOCK: c_int = 0x4000;
const FD_CLOEXEC: c_int = 1;
const F_DUPFD: c_int = 0;
const F_DUPFD_CLOEXEC: c_int = 14;
const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const SEEK_CUR: c_int = 1;
const WNOHANG: c_int = 1;
const WUNTRACED: c_int = 2;
const WCONTINUED: c_int = 8;
const SA_NOCLDSTOP: c_int = 1;
const SA_NOCLDWAIT: c_int = 2;
const SA_RESTART: c_int = mochios_posix_client::signal::SA_RESTART;
const SA_NODEFER: c_int = mochios_posix_client::signal::SA_NODEFER;
const SA_RESETHAND: c_int = mochios_posix_client::signal::SA_RESETHAND;
const SA_SIGINFO: c_int = mochios_posix_client::signal::SA_SIGINFO;
const SA_ONSTACK: c_int = mochios_posix_client::signal_stack::SA_ONSTACK;
const SPAWN_FAIL_EXIT_STATUS: c_int = 127;
const DIR_BUFFER_SIZE: usize = 4096;
const DIRENT_NAME_MAX: usize = 256;
const SIGNAL_UPCALL_STACK_SIZE: usize = 64 * 1024;
const TCSANOW: c_int = 0;
const TCSADRAIN: c_int = 1;
const TCSAFLUSH: c_int = 2;
const TCIFLUSH: c_int = 0;
const TCOFLUSH: c_int = 1;
const TCIOFLUSH: c_int = 2;

const MAX_EXEC_VECTOR_ENTRIES: usize = 256;
const MAX_STARTUP_IMAGE_BYTES: usize = mnu_abi::process_image::MAX_IMAGE_BYTES;

type InitFn = unsafe extern "C" fn();
type CLong = i64;
type Pthread = u32;
type PthreadKey = u32;
type PthreadStart = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type PthreadKeyDestructor = unsafe extern "C" fn(*mut c_void);

const PTHREAD_CREATE_DETACHED: c_int = 0;
const PTHREAD_CREATE_JOINABLE: c_int = 1;
const PTHREAD_STACK_MIN: usize = 16 * 1024;
const PTHREAD_DEFAULT_STACK_SIZE: usize = 1024 * 1024;
const THREAD_FREE: u32 = 0;
const THREAD_STARTING: u32 = 1;
const THREAD_RUNNING: u32 = 2;
const THREAD_EXITED: u32 = 3;
const THREAD_REAPING: u32 = 4;
const THREAD_JOINABLE: u32 = 0;
const THREAD_JOIN_CLAIMED: u32 = 1;
const THREAD_DETACHED: u32 = 2;
const THREAD_REAP_CLAIMED: u32 = 3;
const PTHREAD_CANCEL_ENABLE: u32 = 0;
const PTHREAD_CANCEL_DISABLE: u32 = 1;
const PTHREAD_CANCEL_DEFERRED: u32 = 0;
const PTHREAD_CANCEL_ASYNCHRONOUS: u32 = 1;
const THREAD_KEY_FREE: u32 = 0;
const THREAD_KEY_INITIALIZING: u32 = 1;
const THREAD_KEY_ALLOCATED: u32 = 2;

const CAPABILITY_SERVICE_NAME: &[u8] = b"capability.service";

#[repr(C)]
pub struct Tms {
    tms_utime: u64,
    tms_stime: u64,
    tms_cutime: u64,
    tms_cstime: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NewlibTermios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_cc: [u8; posix_protocol::TERMINAL_CONTROL_CHARACTERS],
    c_ispeed: u32,
    c_ospeed: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NewlibWinSize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

#[repr(C)]
pub struct LockOpaque {
    state: AtomicU32,
    owner: AtomicU64,
    depth: AtomicU32,
    dynamic: bool,
    previous: AtomicUsize,
    next: AtomicUsize,
}

impl LockOpaque {
    const fn new(dynamic: bool) -> Self {
        Self {
            state: AtomicU32::new(0),
            owner: AtomicU64::new(0),
            depth: AtomicU32::new(0),
            dynamic,
            previous: AtomicUsize::new(0),
            next: AtomicUsize::new(0),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SchedParam {
    sched_priority: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PosixSpawnAttr {
    sa_flags: i16,
    sa_pgroup: c_int,
    sa_schedparam: SchedParam,
    sa_schedpolicy: c_int,
    sa_sigdefault: u64,
    sa_sigmask: u64,
}

impl PosixSpawnAttr {
    const fn new() -> Self {
        Self {
            sa_flags: 0,
            sa_pgroup: 0,
            sa_schedparam: SchedParam { sched_priority: 0 },
            sa_schedpolicy: 0,
            sa_sigdefault: 0,
            sa_sigmask: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PthreadAttr {
    // pthread_attr_t is opaque to callers. Keep the SDK's 40-byte, 8-aligned
    // storage contract, not upstream newlib's private field interpretation.
    is_initialized: c_int,
    detachstate: c_int,
    stackaddr: *mut c_void,
    stacksize: usize,
    guardsize: usize,
    reserved: [u32; 2],
}

const _: [(); 40] = [(); core::mem::size_of::<PthreadAttr>()];
const _: [(); 8] = [(); core::mem::align_of::<PthreadAttr>()];

struct ThreadControl {
    state: AtomicU32,
    generation: AtomicU32,
    native_id: AtomicU64,
    // Private newlib locks retain their calling thread's identity across fork.
    // This is never an identity for process-shared pthread synchronization.
    newlib_lock_identity: AtomicU64,
    native_handle: AtomicU32,
    thread_local_base: AtomicU64,
    start: AtomicUsize,
    argument: AtomicUsize,
    result: AtomicUsize,
    stack_base: AtomicUsize,
    stack_size: AtomicUsize,
    owns_stack: AtomicU32,
    reent: AtomicUsize,
    reent_mapping_size: AtomicUsize,
    ptsname_buffer: terminal_name::Buffer,
    joinability: AtomicU32,
    join_waiter: AtomicU32,
    cancel_state: AtomicU32,
    cancel_type: AtomicU32,
    cancel_pending: AtomicU32,
    wait_generation: AtomicU32,
    multiplex_generation: AtomicU64,
    cleanup_head: AtomicUsize,
    stdio_scope: stdio_cancellation::Scope,
    signal_mask: AtomicU64,
    caught_signal_generation: AtomicU64,
    nonrestart_signal_generation: AtomicU64,
    restart_signal_generation: AtomicU64,
    signal_upcall_stack: AtomicUsize,
    signal_upcall_stack_size: AtomicUsize,
    active_native_signal_frame: AtomicUsize,
    active_native_signal_frame_id: AtomicU64,
    next_native_signal_frame_id: AtomicU64,
    native_delivery_defer: AtomicU32,
    active_signal_scope: AtomicUsize,
    callback_resources: callback_resources::Chain,
    active_signal_scope_id: AtomicU64,
    next_signal_scope_id: AtomicU64,
    alternate_stack: mochios_posix_client::signal_stack::AlternateStack,
    specific_values: [AtomicUsize; mochios_posix_client::thread::MAX_THREAD_KEYS],
    specific_generations: [AtomicU32; mochios_posix_client::thread::MAX_THREAD_KEYS],
    specific_destructors_running: AtomicU32,
}

impl ThreadControl {
    const fn new() -> Self {
        Self {
            state: AtomicU32::new(THREAD_FREE),
            generation: AtomicU32::new(0),
            native_id: AtomicU64::new(0),
            newlib_lock_identity: AtomicU64::new(0),
            native_handle: AtomicU32::new(0),
            thread_local_base: AtomicU64::new(0),
            start: AtomicUsize::new(0),
            argument: AtomicUsize::new(0),
            result: AtomicUsize::new(0),
            stack_base: AtomicUsize::new(0),
            stack_size: AtomicUsize::new(0),
            owns_stack: AtomicU32::new(0),
            reent: AtomicUsize::new(0),
            reent_mapping_size: AtomicUsize::new(0),
            ptsname_buffer: terminal_name::Buffer::new(),
            joinability: AtomicU32::new(THREAD_JOINABLE),
            join_waiter: AtomicU32::new(0),
            cancel_state: AtomicU32::new(PTHREAD_CANCEL_ENABLE),
            cancel_type: AtomicU32::new(PTHREAD_CANCEL_DEFERRED),
            cancel_pending: AtomicU32::new(0),
            wait_generation: AtomicU32::new(0),
            multiplex_generation: AtomicU64::new(0),
            cleanup_head: AtomicUsize::new(0),
            stdio_scope: stdio_cancellation::Scope::new(),
            signal_mask: AtomicU64::new(0),
            caught_signal_generation: AtomicU64::new(0),
            nonrestart_signal_generation: AtomicU64::new(0),
            restart_signal_generation: AtomicU64::new(0),
            signal_upcall_stack: AtomicUsize::new(0),
            signal_upcall_stack_size: AtomicUsize::new(0),
            active_native_signal_frame: AtomicUsize::new(0),
            active_native_signal_frame_id: AtomicU64::new(0),
            next_native_signal_frame_id: AtomicU64::new(1),
            native_delivery_defer: AtomicU32::new(0),
            active_signal_scope: AtomicUsize::new(0),
            callback_resources: callback_resources::Chain::with_wait(
                native_mutex_wait,
                native_mutex_wake_all,
            ),
            active_signal_scope_id: AtomicU64::new(0),
            next_signal_scope_id: AtomicU64::new(1),
            alternate_stack: mochios_posix_client::signal_stack::AlternateStack::new(),
            specific_values: [const { AtomicUsize::new(0) };
                mochios_posix_client::thread::MAX_THREAD_KEYS],
            specific_generations: [const { AtomicU32::new(0) };
                mochios_posix_client::thread::MAX_THREAD_KEYS],
            specific_destructors_running: AtomicU32::new(0),
        }
    }
}

struct ThreadKeyControl {
    allocated: AtomicU32,
    generation: AtomicU32,
    destructor: AtomicUsize,
}

impl ThreadKeyControl {
    const fn new() -> Self {
        Self {
            allocated: AtomicU32::new(0),
            generation: AtomicU32::new(0),
            destructor: AtomicUsize::new(0),
        }
    }
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
    ObjectFile = 5,
    ObjectDirectory = 6,
    ObjectStreamRead = 7,
    ObjectStreamWrite = 8,
    ObjectPty = 9,
    ObjectSharedMemory = 10,
    ObjectSocket = 11,
    ObjectDatagram = 12,
    ObjectSpecial = 13,
    ObjectTerminalFile = 14,
}

impl FdKind {
    const fn is_socket(self) -> bool {
        matches!(self, Self::ObjectSocket | Self::ObjectDatagram)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FdObject {
    lower_handle: u64,
    kind: FdKind,
    open_flags: c_int,
    close_owned: bool,
}

type FdEntry = PosixFdEntry<FdObject>;

impl FdObject {
    const fn stdio(kind: FdKind) -> PosixFdEntry<Self> {
        PosixFdEntry {
            handle: Self {
                lower_handle: 0,
                kind,
                open_flags: 0,
                close_owned: false,
            },
            rights: 0,
            descriptor_flags: 0,
        }
    }
}

struct RuntimeFdOps;

impl HandleOps<FdObject> for RuntimeFdOps {
    type Error = c_int;

    fn clone_handle(&mut self, object: FdObject, rights: u64) -> Result<FdObject, Self::Error> {
        if !object.close_owned {
            return Ok(object);
        }
        let lower_handle = syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::HandleDuplicate,
            object.lower_handle,
            rights,
        ))?;
        Ok(FdObject {
            lower_handle,
            close_owned: true,
            ..object
        })
    }

    fn close_handle(&mut self, object: FdObject) {
        let _ = fd_lease::retire(object);
    }
}

fn map_fd_error(error: FdError<c_int>) -> c_int {
    match error {
        FdError::BadDescriptor | FdError::InvalidDescriptor => EBADF,
        FdError::BusyDescriptor => EBUSY,
        FdError::Handle(errno) => errno,
    }
}

fn object_entry(
    lower_handle: u64,
    rights: u64,
    kind: FdKind,
    flags: c_int,
) -> PosixFdEntry<FdObject> {
    PosixFdEntry {
        handle: FdObject {
            lower_handle,
            kind,
            open_flags: flags,
            close_owned: true,
        },
        rights,
        descriptor_flags: if flags & O_CLOEXEC != 0 {
            FD_CLOEXEC as u32
        } else {
            0
        },
    }
}

fn inherited_fd_kind(kind: FdKind) -> Option<u8> {
    match kind {
        FdKind::Unused => None,
        FdKind::Stdin => Some(posix_protocol::INHERITED_FD_KIND_STDIN),
        FdKind::Stdout => Some(posix_protocol::INHERITED_FD_KIND_STDOUT),
        FdKind::Stderr => Some(posix_protocol::INHERITED_FD_KIND_STDERR),
        FdKind::ObjectFile => Some(posix_protocol::INHERITED_FD_KIND_FILE),
        FdKind::ObjectDirectory => Some(posix_protocol::INHERITED_FD_KIND_DIRECTORY),
        FdKind::ObjectStreamRead => Some(posix_protocol::INHERITED_FD_KIND_STREAM_READ),
        FdKind::ObjectStreamWrite => Some(posix_protocol::INHERITED_FD_KIND_STREAM_WRITE),
        FdKind::ObjectPty => Some(posix_protocol::INHERITED_FD_KIND_PTY),
        FdKind::ObjectSharedMemory => Some(posix_protocol::INHERITED_FD_KIND_SHARED_MEMORY),
        FdKind::ObjectSocket => Some(posix_protocol::INHERITED_FD_KIND_SOCKET),
        FdKind::ObjectDatagram => Some(posix_protocol::INHERITED_FD_KIND_DATAGRAM),
        FdKind::ObjectSpecial => Some(posix_protocol::INHERITED_FD_KIND_SPECIAL),
        FdKind::ObjectTerminalFile => Some(posix_protocol::INHERITED_FD_KIND_TERMINAL_FILE),
    }
}

fn fd_kind_from_inherited(kind: u8) -> Option<FdKind> {
    match kind {
        posix_protocol::INHERITED_FD_KIND_STDIN => Some(FdKind::Stdin),
        posix_protocol::INHERITED_FD_KIND_STDOUT => Some(FdKind::Stdout),
        posix_protocol::INHERITED_FD_KIND_STDERR => Some(FdKind::Stderr),
        posix_protocol::INHERITED_FD_KIND_FILE => Some(FdKind::ObjectFile),
        posix_protocol::INHERITED_FD_KIND_DIRECTORY => Some(FdKind::ObjectDirectory),
        posix_protocol::INHERITED_FD_KIND_STREAM_READ => Some(FdKind::ObjectStreamRead),
        posix_protocol::INHERITED_FD_KIND_STREAM_WRITE => Some(FdKind::ObjectStreamWrite),
        posix_protocol::INHERITED_FD_KIND_PTY => Some(FdKind::ObjectPty),
        posix_protocol::INHERITED_FD_KIND_SHARED_MEMORY => Some(FdKind::ObjectSharedMemory),
        posix_protocol::INHERITED_FD_KIND_SOCKET => Some(FdKind::ObjectSocket),
        posix_protocol::INHERITED_FD_KIND_DATAGRAM => Some(FdKind::ObjectDatagram),
        posix_protocol::INHERITED_FD_KIND_SPECIAL => Some(FdKind::ObjectSpecial),
        posix_protocol::INHERITED_FD_KIND_TERMINAL_FILE => Some(FdKind::ObjectTerminalFile),
        _ => None,
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NewlibTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct NewlibRlimit {
    rlim_cur: u64,
    rlim_max: u64,
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

#[repr(C)]
#[derive(Clone, Copy)]
struct NewlibDirent {
    d_ino: u64,
    d_type: u8,
    d_name: [c_char; DIRENT_NAME_MAX],
}

impl NewlibDirent {
    const fn empty() -> Self {
        Self {
            d_ino: 0,
            d_type: 0,
            d_name: [0; DIRENT_NAME_MAX],
        }
    }
}

#[repr(C)]
struct DirStream {
    fd: c_int,
    buffer: [u8; DIR_BUFFER_SIZE],
    buffer_offset: usize,
    buffer_len: usize,
    next_position: Option<u64>,
    current: NewlibDirent,
}

impl DirStream {
    const fn new(fd: c_int) -> Self {
        Self {
            fd,
            buffer: [0; DIR_BUFFER_SIZE],
            buffer_offset: 0,
            buffer_len: 0,
            next_position: None,
            current: NewlibDirent::empty(),
        }
    }
}

impl HeapState {
    const fn new() -> Self {
        Self {
            initialized: false,
            base: 0,
            current_break: 0,
            mapped_end: 0,
            reserved_end: 0,
            pending_release: None,
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
    executable: *const c_char,
    fds: FdTable<FdObject>,
    named_semaphores: mochios_posix_client::named_semaphore::Mappings<u32, 128>,
    timer_values: mochios_posix_client::timer_value::Registry<usize, 128>,
    timer_cleanup: process_timer::CleanupBook,
    thread_clocks: mochios_posix_client::thread_clock::Registry<
        { mochios_posix_client::thread::MAX_THREADS },
    >,
    heap: HeapState,
}

// Safety: raw argv/envp pointers refer to process-wide address-space data.
// Mutable runtime fields are only accessed while `STATE` is locked.
unsafe impl Send for RuntimeState {}

impl RuntimeState {
    const fn new() -> Self {
        Self {
            initialized: false,
            argv: ptr::null_mut(),
            envp: ptr::null_mut(),
            executable: ptr::null(),
            fds: FdTable::new(),
            named_semaphores: mochios_posix_client::named_semaphore::Mappings::new(),
            timer_values: mochios_posix_client::timer_value::Registry::new(),
            timer_cleanup: process_timer::CleanupBook::new(),
            thread_clocks: mochios_posix_client::thread_clock::Registry::new(),
            heap: HeapState::new(),
        }
    }
}

struct RuntimeMutex<T> {
    state: AtomicU32,
    value: UnsafeCell<T>,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignalAction {
    handler: usize,
    sa_mask: u64,
    sa_flags: c_int,
}

impl SignalAction {
    const fn default_action() -> Self {
        Self {
            sa_flags: 0,
            sa_mask: 0,
            handler: 0,
        }
    }
}

impl<T> RuntimeMutex<T> {
    const fn new(value: T) -> Self {
        Self {
            state: AtomicU32::new(0),
            value: UnsafeCell::new(value),
        }
    }

    fn lock(&self) -> RuntimeMutexGuard<'_, T> {
        let delivery = defer_native_delivery();
        native_mutex_acquire(&self.state);
        RuntimeMutexGuard {
            mutex: self,
            _delivery: delivery,
        }
    }
}

// Safety: access to `value` is serialized by the native address-wait mutex.
unsafe impl<T: Send> Sync for RuntimeMutex<T> {}

struct RuntimeMutexGuard<'a, T> {
    mutex: &'a RuntimeMutex<T>,
    _delivery: Option<mochios_posix_client::upcall_guard::Guard<'static>>,
}

impl<T> Deref for RuntimeMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T> DerefMut for RuntimeMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T> Drop for RuntimeMutexGuard<'_, T> {
    fn drop(&mut self) {
        native_mutex_release(&self.mutex.state);
    }
}

struct RuntimeOnce<T> {
    state: AtomicU32,
    value: UnsafeCell<MaybeUninit<T>>,
}

impl<T> RuntimeOnce<T> {
    const fn new() -> Self {
        Self {
            state: AtomicU32::new(0),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn get_or_try_init<E>(&self, initialize: impl FnOnce() -> Result<T, E>) -> Result<&T, E> {
        if self.state.load(Ordering::Acquire) == 2 {
            return Ok(unsafe { (&*self.value.get()).assume_init_ref() });
        }
        let _delivery = defer_native_delivery();
        if self
            .state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            match initialize() {
                Ok(value) => {
                    unsafe { (*self.value.get()).write(value) };
                    self.state.store(2, Ordering::Release);
                    native_mutex_wake_all(&self.state);
                    return Ok(unsafe { (&*self.value.get()).assume_init_ref() });
                }
                Err(error) => {
                    self.state.store(0, Ordering::Release);
                    native_mutex_wake_all(&self.state);
                    return Err(error);
                }
            }
        }
        loop {
            match self.state.load(Ordering::Acquire) {
                2 => return Ok(unsafe { (&*self.value.get()).assume_init_ref() }),
                0 => return self.get_or_try_init(initialize),
                1 => native_mutex_wait(&self.state, 1),
                _ => process_exit(127),
            }
        }
    }
}

// Safety: initialization is serialized and the value is immutable afterward.
unsafe impl<T: Send + Sync> Sync for RuntimeOnce<T> {}

static STATE: RuntimeMutex<RuntimeState> = RuntimeMutex::new(RuntimeState::new());
static SIGNAL_ACTION_UPDATE: RuntimeMutex<()> = RuntimeMutex::new(());
// Default stops suspend the process, not just the signal-delivery thread.
// These counters are private to this runtime's process (including after COW
// fork); only its default-action dispatcher publishes completed stops.
static JOB_STOP_GENERATION: AtomicU64 = AtomicU64::new(0);
static JOB_STOPS_IN_FLIGHT: AtomicU32 = AtomicU32::new(0);

static SIGNAL_ACTIONS: RuntimeMutex<[SignalAction; posix_protocol::SIGNAL_MAX as usize]> =
    RuntimeMutex::new([SignalAction::default_action(); posix_protocol::SIGNAL_MAX as usize]);
static POSIX_CLIENT: RuntimeOnce<PosixClient<SyscallEndpointTransport>> = RuntimeOnce::new();
// A copied syscall result can still describe the parent after a signal
// handler forks. Invalidate in-flight runtime identity lookups in the child.
static FORK_EPOCH: AtomicU64 = AtomicU64::new(0);
static THREADS: [ThreadControl; mochios_posix_client::thread::MAX_THREADS] =
    [const { ThreadControl::new() }; mochios_posix_client::thread::MAX_THREADS];
static THREAD_KEYS: [ThreadKeyControl; mochios_posix_client::thread::MAX_THREAD_KEYS] =
    [const { ThreadKeyControl::new() }; mochios_posix_client::thread::MAX_THREAD_KEYS];

macro_rules! static_newlib_lock {
    ($name:ident) => {
        #[unsafe(no_mangle)]
        pub static $name: LockOpaque = LockOpaque::new(false);
    };
}

static_newlib_lock!(__lock___sfp_recursive_mutex);
static_newlib_lock!(__lock___atexit_recursive_mutex);
static_newlib_lock!(__lock___at_quick_exit_mutex);
static_newlib_lock!(__lock___malloc_recursive_mutex);
static_newlib_lock!(__lock___env_recursive_mutex);
static_newlib_lock!(__lock___tz_mutex);
static_newlib_lock!(__lock___dd_hash_mutex);
static_newlib_lock!(__lock___arc4random_mutex);

#[unsafe(no_mangle)]
pub static mut __env: *mut *mut c_char = ptr::null_mut();

#[repr(C)]
struct IoVec {
    iov_base: *const c_void,
    iov_len: usize,
}

#[repr(C)]
struct IoVecMut {
    iov_base: *mut c_void,
    iov_len: usize,
}

// The checked byte decoder is shared by readv and writev. C pointer constness
// must be their only layout difference; never reinterpret either as a reference.
const _: () = {
    assert!(core::mem::size_of::<IoVec>() == core::mem::size_of::<IoVecMut>());
    assert!(core::mem::offset_of!(IoVec, iov_base) == core::mem::offset_of!(IoVecMut, iov_base));
    assert!(core::mem::offset_of!(IoVec, iov_len) == core::mem::offset_of!(IoVecMut, iov_len));
};

#[repr(C)]
struct Timespec {
    tv_sec: CLong,
    tv_nsec: CLong,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Timeval {
    tv_sec: CLong,
    tv_usec: CLong,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct FdSet {
    bits: [u64; 1],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

const POLLERR: i16 = 0x0008;
const POLLHUP: i16 = 0x0010;
const POLLNVAL: i16 = 0x0020;

#[derive(Clone, Copy)]
struct SpawnSnapshot {
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
}

unsafe extern "C" {
    static __mochios_data_start: u8;
    static __mochios_data_end: u8;
    static __preinit_array_start: InitFn;
    static __preinit_array_end: InitFn;
    static __init_array_start: InitFn;
    static __init_array_end: InitFn;
    static __fini_array_start: InitFn;
    static __fini_array_end: InitFn;
    static mut _impure_ptr: *mut c_void;
    static mut environ: *mut *mut c_char;
    fn __errno() -> *mut c_int;

    fn main(argc: c_int, argv: *mut *mut c_char, envp: *mut *mut c_char) -> c_int;
    fn exit(code: c_int) -> !;
    fn atexit(func: extern "C" fn()) -> c_int;
    fn __sinit(reent: *mut c_void);
    fn __mochios_reent_size() -> usize;
    fn __mochios_reent_initialize(storage: *mut c_void);
    fn __mochios_reent_destroy(storage: *mut c_void);
    fn __mochios_reent_discard(storage: *mut c_void);
    fn malloc(size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
    fn memalign(alignment: usize, size: usize) -> *mut c_void;
    fn getenv(name: *const c_char) -> *mut c_char;
}

#[panic_handler]
// A Rust std consumer supplies its own handler. C-only programs retain this
// fallback; never make an application link two strong lang-item definitions.
#[linkage = "weak"]
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
    executable: *const c_char,
    resource_policy: u64,
    upcall_stack: usize,
    initial_heap: usize,
}

fn align_up(value: usize, align: usize) -> Option<usize> {
    let mask = align.checked_sub(1)?;
    value.checked_add(mask).map(|next| next & !mask)
}

fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

fn state() -> RuntimeMutexGuard<'static, RuntimeState> {
    STATE.lock()
}

fn defer_native_delivery() -> Option<mochios_posix_client::upcall_guard::Guard<'static>> {
    current_thread_control().map(|(_, control)| {
        mochios_posix_client::upcall_guard::Guard::enter(&control.native_delivery_defer)
            .unwrap_or_else(|| process_exit(EOVERFLOW))
    })
}

fn posix_client()
-> Result<&'static PosixClient<SyscallEndpointTransport>, PosixClientError<syscall::SysError>> {
    POSIX_CLIENT.get_or_try_init(PosixClient::from_syscall_launch_context)
}

fn has_posix_environment() -> Result<bool, c_int> {
    match syscall::raw_syscall1(
        syscall::SyscallNumber::LaunchHandleGet,
        posix_protocol::CONTROL_HANDLE_KEY,
    )
    .into_result()
    {
        Ok(_) => Ok(true),
        Err(error) if error.native_error() == Some(mnu_abi::status::Error::NotFound) => Ok(false),
        Err(error) => Err(map_kernel_errno(error.raw())),
    }
}

fn native_process_id() -> Result<u64, syscall::SysError> {
    syscall::execution::identity().map(|identity| identity.process_id)
}

fn native_thread_id() -> Result<u64, syscall::SysError> {
    #[cfg(feature = "trace-io")]
    io_trace::identity(thread_lookup::local_base().is_some());
    syscall::execution::identity().map(|identity| identity.thread_id)
}

fn newlib_lock_identity() -> u64 {
    current_thread_control()
        .map(|(_, control)| control.newlib_lock_identity.load(Ordering::Relaxed))
        .filter(|identity| *identity != 0)
        // Bootstrap may use newlib before a ThreadControl is registered. Its
        // subsequent registration seeds the same identity, without allocation.
        .unwrap_or_else(|| native_thread_id().unwrap_or_else(|_| process_exit(127)))
}

fn native_mutex_wait(state: &AtomicU32, expected: u32) {
    if mochios_posix_client::synchronization::wait_u32(
        state,
        expected,
        syscall::ADDRESS_WAIT_INFINITE,
    )
    .is_err()
    {
        process_exit(127);
    }
}

fn native_mutex_wake_one(state: &AtomicU32) {
    if mochios_posix_client::synchronization::wake_u32(state, 1).is_err() {
        process_exit(127);
    }
}

fn native_mutex_wake_all(state: &AtomicU32) {
    if mochios_posix_client::synchronization::wake_u32(state, usize::MAX).is_err() {
        process_exit(127);
    }
}

fn native_counter_wake_all(state: &AtomicU64) {
    if mochios_posix_client::synchronization::wake_u64(state, usize::MAX).is_err() {
        process_exit(127);
    }
}

fn native_mutex_acquire(state: &AtomicU32) {
    if state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
    {
        return;
    }
    loop {
        if state.swap(2, Ordering::Acquire) == 0 {
            return;
        }
        native_mutex_wait(state, 2);
    }
}

fn native_mutex_try_acquire(state: &AtomicU32) -> bool {
    state
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
}

fn native_mutex_release(state: &AtomicU32) {
    let previous = state.swap(0, Ordering::Release);
    if previous == 0 {
        process_exit(127);
    }
    if previous == 2 {
        native_mutex_wake_one(state);
    }
}

fn thread_token_for(index: usize, control: &ThreadControl) -> Option<Pthread> {
    mochios_posix_client::thread::ThreadToken::new(
        index,
        control.generation.load(Ordering::Acquire),
    )
    .map(mochios_posix_client::thread::ThreadToken::raw)
}

fn thread_control(token: Pthread) -> Option<&'static ThreadControl> {
    let token = mochios_posix_client::thread::ThreadToken::from_raw(token)?;
    let control = THREADS.get(token.slot())?;
    if control.generation.load(Ordering::Acquire) != token.generation()
        || matches!(
            control.state.load(Ordering::Acquire),
            THREAD_FREE | THREAD_REAPING
        )
    {
        return None;
    }
    Some(control)
}

fn reserve_thread_control()
-> Option<(Pthread, &'static ThreadControl, thread_lifecycle::Mutation)> {
    let preparation = thread_lifecycle::mutate();
    for (index, control) in THREADS.iter().enumerate() {
        if control
            .state
            .compare_exchange(
                THREAD_FREE,
                THREAD_STARTING,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            continue;
        }
        let generation = mochios_posix_client::thread::next_generation(
            control.generation.load(Ordering::Relaxed),
        );
        // SAFETY: The FREE -> STARTING transition exclusively claimed this
        // retired slot; its new owner has not been published or started yet.
        unsafe { control.ptsname_buffer.reset() };
        control.generation.store(generation, Ordering::Release);
        control.native_id.store(0, Ordering::Relaxed);
        control.newlib_lock_identity.store(0, Ordering::Relaxed);
        control.native_handle.store(0, Ordering::Relaxed);
        control.start.store(0, Ordering::Relaxed);
        control.argument.store(0, Ordering::Relaxed);
        control.thread_local_base.store(0, Ordering::Relaxed);
        control.result.store(0, Ordering::Relaxed);
        control.stack_base.store(0, Ordering::Relaxed);
        control.stack_size.store(0, Ordering::Relaxed);
        control.owns_stack.store(0, Ordering::Relaxed);
        control.reent.store(0, Ordering::Relaxed);
        control.reent_mapping_size.store(0, Ordering::Relaxed);
        control
            .joinability
            .store(THREAD_JOINABLE, Ordering::Relaxed);
        control.join_waiter.store(0, Ordering::Relaxed);
        control
            .cancel_state
            .store(PTHREAD_CANCEL_ENABLE, Ordering::Relaxed);
        control
            .cancel_type
            .store(PTHREAD_CANCEL_DEFERRED, Ordering::Relaxed);
        control.cancel_pending.store(0, Ordering::Relaxed);
        control.wait_generation.store(0, Ordering::Relaxed);
        control.multiplex_generation.store(0, Ordering::Relaxed);
        control.cleanup_head.store(0, Ordering::Relaxed);
        control.stdio_scope.reset();
        control.signal_mask.store(0, Ordering::Relaxed);
        control.caught_signal_generation.store(0, Ordering::Relaxed);
        control.nonrestart_signal_generation.store(0, Ordering::Relaxed);
        control.restart_signal_generation.store(0, Ordering::Relaxed);
        control.signal_upcall_stack.store(0, Ordering::Relaxed);
        control.signal_upcall_stack_size.store(0, Ordering::Relaxed);
        control.active_native_signal_frame.store(0, Ordering::Relaxed);
        control.active_native_signal_frame_id.store(0, Ordering::Relaxed);
        control.next_native_signal_frame_id.store(1, Ordering::Relaxed);
        control.native_delivery_defer.store(0, Ordering::Relaxed);
        control.active_signal_scope.store(0, Ordering::Relaxed);
        control.active_signal_scope_id.store(0, Ordering::Relaxed);
        control.next_signal_scope_id.store(1, Ordering::Relaxed);
        control.alternate_stack.reset();
        for value in &control.specific_values {
            value.store(0, Ordering::Relaxed);
        }
        for generation in &control.specific_generations {
            generation.store(0, Ordering::Relaxed);
        }
        control
            .specific_destructors_running
            .store(0, Ordering::Relaxed);
        let token = mochios_posix_client::thread::ThreadToken::new(index, generation)?;
        return Some((token.raw(), control, preparation));
    }
    None
}

enum ThreadReclamation {
    ThreadExit,
    ForkChild,
    // The sibling may have been interrupted in a private libc cache update.
    // Preserve its copied memory as part of the inherited VM until exec/exit,
    // without following private pointers or running its destructors.
    ForkLive,
}

fn release_thread_control(control: &ThreadControl) {
    reclaim_thread_control(control, ThreadReclamation::ThreadExit);
}

fn discard_fork_thread_control(control: &ThreadControl) {
    let reason = match control.state.load(Ordering::Acquire) {
        THREAD_EXITED | THREAD_REAPING => ThreadReclamation::ForkChild,
        THREAD_RUNNING => ThreadReclamation::ForkLive,
        _ => process_exit(127),
    };
    reclaim_thread_control(control, reason);
}

fn reclaim_thread_control(control: &ThreadControl, reason: ThreadReclamation) {
    let _reclamation = thread_lifecycle::mutate();
    let keep_private_memory = matches!(reason, ThreadReclamation::ForkLive);
    // Never follow a resource link after its owner's stack has been reclaimed.
    let resources_retired = if keep_private_memory {
        // These foreign frames never resume. Their FD pins were discarded
        // under the copied borrow-book lock before child runtime rebuilding.
        unsafe { control.callback_resources.discard_fork_opaque() }
    } else {
        control.callback_resources.reset_empty()
    };
    if !resources_retired {
        process_exit(127);
    }
    control.active_native_signal_frame.store(0, Ordering::Relaxed);
    control.active_native_signal_frame_id.store(0, Ordering::Relaxed);
    control.active_signal_scope.store(0, Ordering::Relaxed);
    control.active_signal_scope_id.store(0, Ordering::Relaxed);
    thread_reference::replace(control, 0);
    let signal_stack = control.signal_upcall_stack.swap(0, Ordering::Relaxed);
    let signal_stack_size = control.signal_upcall_stack_size.swap(0, Ordering::Relaxed);
    if !keep_private_memory && signal_stack != 0 && signal_stack_size != 0 {
        let _ = syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryUnmap,
            signal_stack as u64,
            signal_stack_size as u64,
        );
    }
    let reent = control.reent.swap(0, Ordering::Relaxed);
    let reent_mapping_size = control.reent_mapping_size.swap(0, Ordering::Relaxed);
    if !keep_private_memory && reent != 0 && reent_mapping_size != 0 {
        // Normal reent destruction may flush streams. Internal reclamation
        // must not abandon its owned TCB/mappings at a cancellation point;
        // fork-child discard suppresses those callbacks entirely.
        let caller = current_thread_control();
        let previous = caller.map(|(_, caller)| {
            caller.cancel_state.swap(PTHREAD_CANCEL_DISABLE, Ordering::AcqRel)
        });
        unsafe {
            match reason {
                ThreadReclamation::ThreadExit => __mochios_reent_destroy(reent as *mut c_void),
                ThreadReclamation::ForkChild => __mochios_reent_discard(reent as *mut c_void),
                ThreadReclamation::ForkLive => unreachable!(),
            }
        }
        if let (Some((_, caller)), Some(previous)) = (caller, previous) {
            caller.cancel_state.store(previous, Ordering::Release);
        }
        let _ = syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryUnmap,
            reent as u64,
            reent_mapping_size as u64,
        );
    }
    let stack_base = control.stack_base.swap(0, Ordering::Relaxed);
    let stack_size = control.stack_size.swap(0, Ordering::Relaxed);
    let owns_stack = control.owns_stack.swap(0, Ordering::Relaxed) != 0;
    if !keep_private_memory && owns_stack && stack_base != 0 && stack_size != 0 {
        let _ = syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryUnmap,
            stack_base as u64,
            stack_size as u64,
        );
    }
    control.native_id.store(0, Ordering::Relaxed);
    control.newlib_lock_identity.store(0, Ordering::Relaxed);
    control.thread_local_base.store(0, Ordering::Relaxed);
    control.start.store(0, Ordering::Relaxed);
    control.argument.store(0, Ordering::Relaxed);
    control.result.store(0, Ordering::Relaxed);
    control
        .joinability
        .store(THREAD_JOINABLE, Ordering::Relaxed);
    control.join_waiter.store(0, Ordering::Relaxed);
    control.cancel_pending.store(0, Ordering::Relaxed);
    control.wait_generation.store(0, Ordering::Relaxed);
    control.multiplex_generation.store(0, Ordering::Relaxed);
    control.cleanup_head.store(0, Ordering::Relaxed);
    control.stdio_scope.reset();
    control.signal_mask.store(0, Ordering::Relaxed);
    control.caught_signal_generation.store(0, Ordering::Relaxed);
    control.nonrestart_signal_generation.store(0, Ordering::Relaxed);
    control.restart_signal_generation.store(0, Ordering::Relaxed);
    for value in &control.specific_values {
        value.store(0, Ordering::Relaxed);
    }
    for generation in &control.specific_generations {
        generation.store(0, Ordering::Relaxed);
    }
    control
        .specific_destructors_running
        .store(0, Ordering::Relaxed);
    control.state.store(THREAD_FREE, Ordering::Release);
    native_mutex_wake_all(&control.state);
}

fn allocate_thread_reent(control: &ThreadControl) -> Result<(), c_int> {
    let size = unsafe { __mochios_reent_size() };
    let mapping_size = align_up(size, PAGE_SIZE).ok_or(EOVERFLOW)?;
    if size == 0 || mapping_size == 0 {
        return Err(EINVAL);
    }
    let address =
        address_space::current()?.map(0, mapping_size as u64, NATIVE_READ_WRITE, 0, 0, 0)? as usize;
    control
        .reent_mapping_size
        .store(mapping_size, Ordering::Relaxed);
    control.reent.store(address, Ordering::Release);
    unsafe { __mochios_reent_initialize(address as *mut c_void) };
    Ok(())
}

fn reap_detached_threads() {
    for control in &THREADS {
        if control.state.load(Ordering::Acquire) == THREAD_EXITED
            && control
                .joinability
                .compare_exchange(
                    THREAD_DETACHED,
                    THREAD_REAP_CLAIMED,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            if native_thread_retired(control) == Ok(true) {
                control.state.store(THREAD_REAPING, Ordering::Release);
                release_thread_control(control);
            } else {
                // Keep the live thread's TCB visible to callbacks during exit.
                control.joinability.store(THREAD_DETACHED, Ordering::Release);
            }
        }
    }
}

fn current_thread_control() -> Option<(Pthread, &'static ThreadControl)> {
    static CACHE: thread_lookup::TokenCache = thread_lookup::TokenCache::new();
    loop {
        let epoch = FORK_EPOCH.load(Ordering::Acquire);
        // Registered nonzero TLS bases are runtime-private thread identities,
        // not authentication. Native threads without a private TLS base keep
        // the kernel-identity path; nothing here changes IPC sender identity.
        let from_tls = thread_lookup::local_base().and_then(|base| {
            let revision = thread_lifecycle::stable_revision();
            if let Some(revision) = revision {
                if let Some(token) = CACHE.get(base, revision) {
                    if let Some(control) = thread_control(token) {
                        if control.thread_local_base.load(Ordering::Acquire) == base
                            && thread_lifecycle::stable_revision() == Some(revision)
                        {
                            return Some((token, control));
                        }
                    }
                }
            }
            let mut matches = THREADS.iter().enumerate().filter(|(_, control)| {
                let state = control.state.load(Ordering::Acquire);
                state != THREAD_FREE
                    && state != THREAD_REAPING
                    && control.thread_local_base.load(Ordering::Acquire) == base
            });
            let (index, control) = matches.next()?;
            // An ambiguous registration cannot establish a local identity.
            if matches.next().is_none() {
                thread_token_for(index, control).map(|token| {
                    if let Some(revision) = revision {
                        if thread_lifecycle::stable_revision() == Some(revision) {
                            CACHE.insert(base, revision, token);
                        }
                    }
                    (token, control)
                })
            } else {
                None
            }
        });
        let current = from_tls.or_else(|| {
            native_thread_id().ok().and_then(|native_id| {
                THREADS.iter().enumerate().find_map(|(index, control)| {
                    let state = control.state.load(Ordering::Acquire);
                    (state != THREAD_FREE
                        && state != THREAD_REAPING
                        && control.native_id.load(Ordering::Acquire) == native_id)
                        .then(|| thread_token_for(index, control).map(|token| (token, control)))
                        .flatten()
                })
            })
        });
        if FORK_EPOCH.load(Ordering::Acquire) == epoch {
            return current;
        }
    }
}

fn register_current_thread() -> Option<(Pthread, &'static ThreadControl)> {
    let current = register_thread_control()?;
    // Bootstrap processes may receive their endpoint after libc initialized
    // the native thread. Enter its POSIX signal environment before the first
    // POSIX operation, rather than treating a missing mask as an empty one.
    if current.1.signal_upcall_stack.load(Ordering::Acquire) == 0
        && has_posix_environment().ok()?
    {
        setup_signal_delivery(current.1, None).ok()?;
    }
    Some(current)
}

fn register_thread_control() -> Option<(Pthread, &'static ThreadControl)> {
    if let Some(current) = current_thread_control() {
        return Some(current);
    }
    reap_detached_threads();
    let native_id = native_thread_id().ok()?;
    let (token, control, _preparation) = reserve_thread_control()?;
    control.native_id.store(native_id, Ordering::Relaxed);
    control.newlib_lock_identity.store(native_id, Ordering::Relaxed);
    control.state.store(THREAD_RUNNING, Ordering::Release);
    if allocate_thread_reent(control).is_err() {
        control.state.store(THREAD_REAPING, Ordering::Relaxed);
        release_thread_control(control);
        return None;
    }
    if setup_signal_delivery(control, None).is_err() {
        control.state.store(THREAD_REAPING, Ordering::Relaxed);
        release_thread_control(control);
        return None;
    }
    Some((token, control))
}

fn register_initial_thread() -> Option<(Pthread, &'static ThreadControl)> {
    if let Some(current) = current_thread_control() {
        return Some(current);
    }
    let native_id = native_thread_id().ok()?;
    let (token, control, _preparation) = reserve_thread_control()?;
    control.native_id.store(native_id, Ordering::Relaxed);
    control.newlib_lock_identity.store(native_id, Ordering::Relaxed);
    // The current initial-runtime TCB ABI places its own base in its first
    // word. Other runtime-created threads explicitly use a zero TLS base.
    let tls_base: u64;
    unsafe {
        core::arch::asm!("mov {}, fs:[0]", out(reg) tls_base, options(nostack, readonly, preserves_flags));
    }
    control.thread_local_base.store(tls_base, Ordering::Relaxed);
    control
        .reent
        .store(unsafe { _impure_ptr } as usize, Ordering::Relaxed);
    control.state.store(THREAD_RUNNING, Ordering::Release);
    Some((token, control))
}

fn allocate_signal_stack(control: &ThreadControl) -> Result<(), c_int> {
    if has_posix_environment()? {
        let stack = address_space::current()?.map(
            0,
            SIGNAL_UPCALL_STACK_SIZE as u64,
            NATIVE_READ_WRITE,
            0,
            0,
            0,
        )? as usize;
        control
            .signal_upcall_stack_size
            .store(SIGNAL_UPCALL_STACK_SIZE, Ordering::Relaxed);
        control.signal_upcall_stack.store(stack, Ordering::Release);
    }
    Ok(())
}

fn setup_signal_delivery(
    control: &ThreadControl,
    prepared_stack: Option<usize>,
) -> Result<(), c_int> {
    // Native bootstrap services run before a POSIX endpoint can be delegated.
    // An inherited endpoint still requires successful registration below.
    if !has_posix_environment()? {
        if control.native_handle.load(Ordering::Acquire) == 0 {
            let handle = syscall_errno(syscall::raw_syscall0(
                syscall::SyscallNumber::ThreadHandleCreate,
            ))?;
            let handle = u32::try_from(handle).map_err(|_| EOVERFLOW)?;
            thread_reference::replace(control, handle);
        }
        return Ok(());
    }
    // Registration can make a pending signal deliverable immediately. Keep
    // callbacks deferred until the new native stack and identity are both
    // published, including when a fork child still has copied active frames.
    let _preparation =
        mochios_posix_client::upcall_guard::Guard::enter(&control.native_delivery_defer)
            .ok_or(EOVERFLOW)?;
    // Restore an existing native thread's mask after exec, or seed a new
    // fork/pthread thread from its inherited cache before upcalls can run.
    service_signal_mask(
        control,
        posix_protocol::SIGNAL_MASK_INITIALIZE,
        control.signal_mask.load(Ordering::Acquire),
    )?;
    let stack = match prepared_stack {
        Some(stack) if stack != 0 => stack,
        Some(_) => return Err(EINVAL),
        None => address_space::current()?.map(
            0,
            SIGNAL_UPCALL_STACK_SIZE as u64,
            NATIVE_READ_WRITE,
            0,
            0,
            0,
        )? as usize,
    };
    let config = syscall::ThreadUpcallConfig {
        entry: posix_signal_upcall as *const () as u64,
        stack_base: stack as u64,
        stack_size: SIGNAL_UPCALL_STACK_SIZE as u64,
        flags: syscall::THREAD_UPCALL_EXCEPTIONS,
        defer_word: control.native_delivery_defer.as_ptr() as u64,
        reserved: [0; 3],
    };
    let install = syscall_errno(syscall::raw_syscall2(
        syscall::SyscallNumber::ThreadUpcallInstall,
        (&config as *const syscall::ThreadUpcallConfig) as u64,
        core::mem::size_of::<syscall::ThreadUpcallConfig>() as u64,
    ));
    if let Err(error) = install {
        let _ = syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryUnmap,
            stack as u64,
            SIGNAL_UPCALL_STACK_SIZE as u64,
        );
        return Err(error);
    }
    let handle = match syscall_errno(syscall::raw_syscall0(
        syscall::SyscallNumber::ThreadHandleCreate,
    ))
    .and_then(|handle| u32::try_from(handle).map_err(|_| EOVERFLOW))
    {
        Ok(handle) => handle,
        Err(error) => {
            let _ = syscall::raw_syscall2(
                syscall::SyscallNumber::MemoryUnmap,
                stack as u64,
                SIGNAL_UPCALL_STACK_SIZE as u64,
            );
            return Err(error);
        }
    };
    // Publish before registration can trigger a pending-signal upcall. A
    // handler on this starting thread may use its own pthread identity.
    thread_reference::replace(control, handle);
    let registration = posix_client()
        .map_err(map_posix_client_error)
        .and_then(|client| {
            client
                .register_signal_thread(ObjectHandleAttachment {
                    handle,
                    rights: syscall::HANDLE_RIGHT_WAIT | syscall::HANDLE_RIGHT_SIGNAL,
                })
                .map_err(map_posix_client_error)
        });
    if let Err(error) = registration {
        thread_reference::replace(control, 0);
        let _ = syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryUnmap,
            stack as u64,
            SIGNAL_UPCALL_STACK_SIZE as u64,
        );
        return Err(error);
    }
    control
        .signal_upcall_stack_size
        .store(SIGNAL_UPCALL_STACK_SIZE, Ordering::Relaxed);
    control.signal_upcall_stack.store(stack, Ordering::Release);
    Ok(())
}

fn thread_key_control(
    key: PthreadKey,
) -> Option<(
    mochios_posix_client::thread::ThreadKeyToken,
    &'static ThreadKeyControl,
)> {
    let token = mochios_posix_client::thread::ThreadKeyToken::from_raw(key)?;
    let control = THREAD_KEYS.get(token.slot())?;
    if control.allocated.load(Ordering::Acquire) != THREAD_KEY_ALLOCATED
        || control.generation.load(Ordering::Acquire) != token.generation()
    {
        return None;
    }
    Some((token, control))
}

fn run_thread_specific_destructors(control: &ThreadControl) {
    if control
        .specific_destructors_running
        .swap(1, Ordering::AcqRel)
        != 0
    {
        return;
    }
    for _ in 0..mochios_posix_client::thread::DESTRUCTOR_ITERATIONS {
        let mut called_destructor = false;
        for (slot, key_control) in THREAD_KEYS.iter().enumerate() {
            if key_control.allocated.load(Ordering::Acquire) != THREAD_KEY_ALLOCATED {
                continue;
            }
            let generation = key_control.generation.load(Ordering::Acquire);
            if control.specific_generations[slot].load(Ordering::Acquire) != generation {
                continue;
            }
            let value = control.specific_values[slot].swap(0, Ordering::AcqRel);
            if value == 0 {
                continue;
            }
            let destructor = key_control.destructor.load(Ordering::Acquire);
            if destructor != 0 {
                called_destructor = true;
                let destructor: PthreadKeyDestructor = unsafe { core::mem::transmute(destructor) };
                unsafe { destructor(value as *mut c_void) };
            }
        }
        if !called_destructor {
            break;
        }
    }
}

fn finish_thread(control: &ThreadControl, result: *mut c_void) -> ! {
    // Exit/cancellation cleanup must not be interrupted by another pending
    // cancellation, including when a TLS destructor calls a cancellation point.
    control
        .cancel_state
        .store(PTHREAD_CANCEL_DISABLE, Ordering::Release);
    control
        .cancel_type
        .store(PTHREAD_CANCEL_DEFERRED, Ordering::Release);
    {
        let _delivery =
            mochios_posix_client::upcall_guard::Guard::enter(&control.native_delivery_defer)
                .unwrap_or_else(|| process_exit(EOVERFLOW));
        // ThreadExit does not unwind Rust frames. All runtime-owned scopes
        // must be retired before application cleanup or stack reclamation.
        unsafe { control.callback_resources.abandon_from(0) };
    }
    unsafe { thread_cleanup::drain(&control.cleanup_head) };
    run_thread_specific_destructors(control);
    {
        let _delivery = defer_native_delivery();
        process_timer::thread_exit(control.native_id.load(Ordering::Acquire), || {
            control.result.store(result as usize, Ordering::Relaxed);
            control.state.store(THREAD_EXITED, Ordering::Release);
        });
    }
    notify_join_waiter(control);
    native_mutex_wake_all(&control.state);
    let _ = syscall::raw_syscall1(syscall::SyscallNumber::ThreadExit, 0);
    loop {
        core::hint::spin_loop();
    }
}

// THREAD_EXITED publishes the result, but the thread still executes WakeAddress
// and ThreadExit afterwards. Its stacks and reent must survive that interval,
// including any upcall delivered on the way out.
fn native_thread_retired(control: &ThreadControl) -> Result<bool, c_int> {
    thread_reference::with_control(control, |handle| {
        let mut status = syscall::ThreadStatus::default();
        match syscall::raw_syscall2(
            syscall::SyscallNumber::ThreadHandleStatus,
            u64::from(handle),
            (&mut status as *mut syscall::ThreadStatus) as u64,
        )
        .into_result()
        {
            Ok(_) => Ok(status.state == mnu_abi::THREAD_STATE_TERMINATED),
            // Only absence of the retained thread target proves retirement.
            // Invalid selectors/authority or failed copies must not free stacks.
            Err(error) if error.native_error() == Some(mnu_abi::status::Error::NotFound) => Ok(true),
            Err(error) => Err(map_kernel_errno(error.raw())),
        }
    })
}

unsafe extern "C" fn pthread_start_trampoline(argument: *mut c_void) -> ! {
    let preparation = thread_lifecycle::mutate();
    let control = unsafe { &*argument.cast::<ThreadControl>() };
    let native_id = native_thread_id().unwrap_or_else(|_| process_exit(127));
    control.native_id.store(native_id, Ordering::Relaxed);
    control
        .newlib_lock_identity
        .store(native_id, Ordering::Relaxed);
    if setup_signal_delivery(
        control,
        Some(control.signal_upcall_stack.load(Ordering::Acquire)),
    )
    .is_err()
    {
        process_exit(127);
    }
    let _ = control.state.compare_exchange(
        THREAD_STARTING,
        THREAD_RUNNING,
        Ordering::Release,
        Ordering::Relaxed,
    );
    native_mutex_wake_all(&control.state);
    drop(preparation);
    let start_address = control.start.load(Ordering::Acquire);
    if start_address == 0 {
        process_exit(127);
    }
    let start: PthreadStart = unsafe { core::mem::transmute(start_address) };
    let result = unsafe { start(control.argument.load(Ordering::Relaxed) as *mut c_void) };
    finish_thread(control, result)
}

#[unsafe(no_mangle)]
pub extern "C" fn __getreent() -> *mut c_void {
    // libc allocation is also used inside POSIX attachment and by native-only
    // services. Looking up reent must neither attach recursively nor add an
    // endpoint query to every allocator invocation.
    let (_, control) = register_thread_control().unwrap_or_else(|| process_exit(127));
    let reent = control.reent.load(Ordering::Acquire);
    if reent == 0 {
        process_exit(127);
    }
    reent as *mut c_void
}

fn set_errno(value: c_int) {
    unsafe {
        *__errno() = value;
    }
}

fn special_stat(file_type: u32) -> NewlibStat {
    NewlibStat {
        st_dev: 0,
        st_ino: 0,
        st_mode: file_type | 0o600,
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        st_size: 0,
        st_atim: NewlibTimespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_mtim: NewlibTimespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_ctim: NewlibTimespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_blksize: 4096,
        st_blocks: 0,
        st_spare4: [0; 2],
    }
}

fn stream_stat() -> NewlibStat {
    special_stat(0o010000)
}

fn pty_stat() -> NewlibStat {
    special_stat(0o020000)
}

fn translate_posix_stat(status: &PosixFileStatus) -> Result<NewlibStat, c_int> {
    Ok(NewlibStat {
        st_dev: u16::try_from(status.device).map_err(|_| EOVERFLOW)?,
        st_ino: u16::try_from(status.inode).map_err(|_| EOVERFLOW)?,
        st_mode: status.mode,
        st_nlink: u16::try_from(status.link_count).map_err(|_| EOVERFLOW)?,
        st_uid: u16::try_from(status.uid).map_err(|_| EOVERFLOW)?,
        st_gid: u16::try_from(status.gid).map_err(|_| EOVERFLOW)?,
        st_rdev: u16::try_from(status.special_device).map_err(|_| EOVERFLOW)?,
        st_size: status.size,
        st_atim: NewlibTimespec {
            tv_sec: status.access_time_seconds,
            tv_nsec: status.access_time_nanoseconds,
        },
        st_mtim: NewlibTimespec {
            tv_sec: status.modification_time_seconds,
            tv_nsec: status.modification_time_nanoseconds,
        },
        st_ctim: NewlibTimespec {
            tv_sec: status.change_time_seconds,
            tv_nsec: status.change_time_nanoseconds,
        },
        st_blksize: status.block_size,
        st_blocks: status.blocks,
        st_spare4: [0; 2],
    })
}

fn map_kernel_errno(raw: i64) -> c_int {
    mochios_posix_client::newlib_errno::from_status(raw)
}

fn map_posix_client_error(error: PosixClientError<mochi_user_syscall::SysError>) -> c_int {
    match error {
        PosixClientError::Remote(status) => map_kernel_errno(i64::from(status)),
        PosixClientError::Transport(error) => map_kernel_errno(error.raw()),
        PosixClientError::ResponseTooLarge => ERANGE,
        PosixClientError::Protocol(_)
        | PosixClientError::RequestTooLarge
        | PosixClientError::MismatchedResponse => EIO,
    }
}

fn syscall_errno(result: syscall::RawSyscallResult) -> Result<u64, c_int> {
    result
        .into_result()
        .map_err(|error| map_kernel_errno(error.raw()))
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
    let mut auxiliary = unsafe { cursor.add(1).cast::<usize>() };
    let mut executable = ptr::null();
    let mut resource_policy = 0;
    let mut upcall_stack = 0;
    let mut initial_heap = 0;
    while unsafe { auxiliary.read() } != 0 {
        if unsafe { auxiliary.read() } == 31 {
            executable = unsafe { auxiliary.add(1).read() } as *const c_char;
        }
        match unsafe { auxiliary.read() } as u64 {
            mochios_posix_client::process_image::AT_RESOURCE_POLICY => {
                resource_policy = unsafe { auxiliary.add(1).read() } as u64;
            }
            mochios_posix_client::process_image::AT_UPCALL_STACK => {
                upcall_stack = unsafe { auxiliary.add(1).read() };
            }
            mochios_posix_client::process_image::AT_INITIAL_HEAP => {
                initial_heap = unsafe { auxiliary.add(1).read() };
            }
            _ => {}
        }
        auxiliary = unsafe { auxiliary.add(2) };
    }
    StackView {
        argc,
        argv,
        envp,
        stack_top: sp as usize,
        executable,
        resource_policy,
        upcall_stack,
        initial_heap,
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

fn find_env_value_bytes(name: &[u8], out: &mut [u8]) -> Option<usize> {
    let environ_ptr = unsafe { environ };
    if environ_ptr.is_null() {
        return None;
    }
    let mut cursor = environ_ptr;
    let prefix_len = name.len();
    loop {
        let entry = unsafe { cursor.read() };
        if entry.is_null() {
            return None;
        }
        let bytes = unsafe { c_bytes(entry.cast_const()) };
        if bytes.len() > prefix_len + 1 && bytes[..prefix_len] == *name && bytes[prefix_len] == b'='
        {
            let value = &bytes[prefix_len + 1..];
            let copy_len = core::cmp::min(out.len(), value.len());
            out[..copy_len].copy_from_slice(&value[..copy_len]);
            return Some(copy_len);
        }
        cursor = unsafe { cursor.add(1) };
    }
}

fn read_env_u64(name: &[u8]) -> Option<u64> {
    let mut buf = [0u8; 32];
    let len = find_env_value_bytes(name, &mut buf)?;
    parse_decimal(&buf[..len]).map(|v| v as u64)
}

fn read_env_path(name: &[u8]) -> Option<[u8; 256]> {
    let mut buf = [0u8; 256];
    let len = find_env_value_bytes(name, &mut buf)?;
    let mut out = [0u8; 256];
    out[..len].copy_from_slice(&buf[..len]);
    Some(out)
}

fn capability_class_from_string(name: &str) -> CapabilityClass {
    match mnu_abi::capability::metadata(name).map(|metadata| metadata.classification) {
        Some(mnu_abi::capability::CapabilityClassification::UserGrantable) => {
            CapabilityClass::UserGrantable
        }
        Some(mnu_abi::capability::CapabilityClassification::Privileged) => {
            CapabilityClass::Privileged
        }
        Some(mnu_abi::capability::CapabilityClassification::SystemOnly) | None => {
            CapabilityClass::SystemOnly
        }
    }
}

fn request_capability_from_shell(
    capability: &str,
    resource: Option<&str>,
    reason: Option<&str>,
) -> Option<CapabilityDecision> {
    let prompt_mode = read_env_path(b"MOCHI_PROMPT_MODE")?;
    let prompt_mode_len = prompt_mode
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(prompt_mode.len());
    if &prompt_mode[..prompt_mode_len] != b"interactive" {
        return Some(CapabilityDecision::Deny);
    }
    let shell_endpoint = read_env_u64(b"MOCHI_SHELL_ENDPOINT")?;
    let executable = read_env_path(b"MOCHI_EXECUTABLE_PATH")?;
    let executable_len = executable
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(executable.len());
    let executable_path = core::str::from_utf8(&executable[..executable_len]).ok()?;
    let class = capability_class_from_string(capability);
    let mut request = CapabilityPromptRequest {
        opcode: CAPABILITY_PROMPT_OPCODE,
        process_id: native_process_id().unwrap_or(0),
        executable: CapabilityExecutableIdentity::default(),
        capability_class: class,
        capability_len: 0,
        resource: CapabilityResourceDescriptor::default(),
        reason_len: 0,
        interactive: 1,
        decision_scope: 0,
        reserved0: 0,
        capability: [0; MAX_CAPABILITY_NAME_LEN],
        reason: [0; MAX_REASON_LEN],
    };
    let exec_bytes = executable_path.as_bytes();
    if exec_bytes.len() > request.executable.path.len() {
        return None;
    }
    request.executable.path_len = exec_bytes.len() as u16;
    request.executable.path[..exec_bytes.len()].copy_from_slice(exec_bytes);
    let cap_bytes = capability.as_bytes();
    if cap_bytes.len() > request.capability.len() {
        return None;
    }
    request.capability_len = cap_bytes.len() as u16;
    request.capability[..cap_bytes.len()].copy_from_slice(cap_bytes);
    if let Some(resource) = resource {
        let res_bytes = resource.as_bytes();
        if res_bytes.len() > request.resource.path.len() {
            return None;
        }
        request.resource.kind = 1;
        request.resource.path_len = res_bytes.len() as u16;
        request.resource.path[..res_bytes.len()].copy_from_slice(res_bytes);
    }
    if let Some(reason) = reason {
        let reason_bytes = reason.as_bytes();
        if reason_bytes.len() > request.reason.len() {
            return None;
        }
        request.reason_len = reason_bytes.len() as u16;
        request.reason[..reason_bytes.len()].copy_from_slice(reason_bytes);
    }
    let mut reply = [0u8; 8];
    let msg = syscall::call5(
        syscall::SyscallNumber::IpcCall,
        shell_endpoint,
        (&request as *const CapabilityPromptRequest) as u64,
        core::mem::size_of::<CapabilityPromptRequest>() as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    )
    .ok()?;
    let len = (msg & 0xffff_ffff) as usize;
    if len < 4 {
        return None;
    }
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&reply[..4]);
    match u32::from_le_bytes(raw) {
        x if x == CapabilityDecision::AllowOnce as u32 => Some(CapabilityDecision::AllowOnce),
        x if x == CapabilityDecision::AllowForProcess as u32 => {
            Some(CapabilityDecision::AllowForProcess)
        }
        x if x == CapabilityDecision::AllowPersistently as u32 => {
            Some(CapabilityDecision::AllowPersistently)
        }
        x if x == CapabilityDecision::AllowAllUserGrantable as u32 => {
            Some(CapabilityDecision::AllowAllUserGrantable)
        }
        _ => Some(CapabilityDecision::Deny),
    }
}

fn fill_capability_request(
    opcode: u32,
    capability: &str,
    resource: Option<&str>,
    reason: Option<&str>,
    interactive: bool,
) -> Option<CapabilityPromptRequest> {
    let executable = read_env_path(b"MOCHI_EXECUTABLE_PATH")?;
    let executable_len = executable
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(executable.len());
    let executable_path = core::str::from_utf8(&executable[..executable_len]).ok()?;
    let class = capability_class_from_string(capability);
    let mut request = CapabilityPromptRequest {
        opcode,
        process_id: native_process_id().unwrap_or(0),
        executable: CapabilityExecutableIdentity::default(),
        capability_class: class,
        capability_len: 0,
        resource: CapabilityResourceDescriptor::default(),
        reason_len: 0,
        interactive: interactive as u8,
        decision_scope: 0,
        reserved0: 0,
        capability: [0; MAX_CAPABILITY_NAME_LEN],
        reason: [0; MAX_REASON_LEN],
    };
    let exec_bytes = executable_path.as_bytes();
    if exec_bytes.len() > request.executable.path.len() {
        return None;
    }
    request.executable.path_len = exec_bytes.len() as u16;
    request.executable.path[..exec_bytes.len()].copy_from_slice(exec_bytes);
    let cap_bytes = capability.as_bytes();
    if cap_bytes.len() > request.capability.len() {
        return None;
    }
    request.capability_len = cap_bytes.len() as u16;
    request.capability[..cap_bytes.len()].copy_from_slice(cap_bytes);
    if let Some(resource) = resource {
        let res_bytes = resource.as_bytes();
        if res_bytes.len() > request.resource.path.len() {
            return None;
        }
        request.resource.kind = 1;
        request.resource.path_len = res_bytes.len() as u16;
        request.resource.path[..res_bytes.len()].copy_from_slice(res_bytes);
    }
    if let Some(reason) = reason {
        let reason_bytes = reason.as_bytes();
        if reason_bytes.len() > request.reason.len() {
            return None;
        }
        request.reason_len = reason_bytes.len() as u16;
        request.reason[..reason_bytes.len()].copy_from_slice(reason_bytes);
    }
    Some(request)
}

fn request_persistent_capability(
    capability: &str,
    resource: Option<&str>,
    reason: Option<&str>,
) -> bool {
    let request = match fill_capability_request(
        CAPABILITY_PERSISTENT_QUERY_OPCODE,
        capability,
        resource,
        reason,
        false,
    ) {
        Some(request) => request,
        None => return false,
    };
    let endpoint = match syscall::call2(
        syscall::SyscallNumber::FindProcessByName,
        CAPABILITY_SERVICE_NAME.as_ptr() as u64,
        CAPABILITY_SERVICE_NAME.len() as u64,
    ) {
        Ok(endpoint) if endpoint != 0 => endpoint,
        _ => return false,
    };
    let mut reply = [0u8; 8];
    let msg = match syscall::call5(
        syscall::SyscallNumber::IpcCall,
        endpoint,
        (&request as *const CapabilityPromptRequest) as u64,
        core::mem::size_of::<CapabilityPromptRequest>() as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    ) {
        Ok(msg) => msg,
        Err(_) => return false,
    };
    let len = (msg & 0xffff_ffff) as usize;
    if len < 8 {
        return false;
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&reply[..8]);
    u64::from_le_bytes(raw) == 0
}

fn drop_capability(capability: &str) {
    let bytes = capability.as_bytes();
    let _ = syscall::raw_syscall2(
        syscall::SyscallNumber::CapDrop,
        bytes.as_ptr() as u64,
        bytes.len() as u64,
    );
}

fn open_requires_write_access(flags: c_int) -> bool {
    let access_mode = flags & 0x3;
    access_mode != 0 || (flags & (0x0008 | 0x0200 | 0x0400)) != 0
}

fn posix_open_options(flags: c_int) -> Result<u32, c_int> {
    const O_APPEND: c_int = 0x0008;
    const O_CREAT: c_int = 0x0200;
    const O_TRUNC: c_int = 0x0400;
    const O_EXCL: c_int = 0x0800;
    const O_NONBLOCK: c_int = 0x4000;
    const O_NOFOLLOW: c_int = 0x100000;
    const O_DIRECTORY: c_int = 0x200000;
    const SUPPORTED: c_int = 0x3
        | O_APPEND
        | O_CREAT
        | O_TRUNC
        | O_EXCL
        | O_NONBLOCK
        | O_CLOEXEC
        | O_NOFOLLOW
        | O_DIRECTORY;
    if flags & !SUPPORTED != 0 {
        return Err(EINVAL);
    }
    let mut options = match flags & 0x3 {
        0 => posix_protocol::OPEN_READ,
        1 => posix_protocol::OPEN_WRITE,
        2 => posix_protocol::OPEN_READ | posix_protocol::OPEN_WRITE,
        _ => return Err(EINVAL),
    };
    for (source, target) in [
        (O_APPEND, posix_protocol::OPEN_APPEND),
        (O_CREAT, posix_protocol::OPEN_CREATE),
        (O_TRUNC, posix_protocol::OPEN_TRUNCATE),
        (O_EXCL, posix_protocol::OPEN_EXCLUSIVE),
        (O_NONBLOCK, posix_protocol::OPEN_NONBLOCK),
        (O_NOFOLLOW, posix_protocol::OPEN_NOFOLLOW),
        (O_DIRECTORY, posix_protocol::OPEN_DIRECTORY),
    ] {
        if flags & source != 0 {
            options |= target;
        }
    }
    Ok(options | posix_protocol::OPEN_CURSOR_RECORDS)
}

fn posix_mutable_status_flags(flags: c_int) -> u32 {
    const O_APPEND: c_int = 0x0008;
    const O_NONBLOCK: c_int = 0x4000;
    let mut result = 0;
    if flags & O_APPEND != 0 {
        result |= posix_protocol::OPEN_APPEND;
    }
    if flags & O_NONBLOCK != 0 {
        result |= posix_protocol::OPEN_NONBLOCK;
    }
    result
}

fn newlib_mutable_status_flags(flags: u32) -> c_int {
    const O_APPEND: c_int = 0x0008;
    const O_NONBLOCK: c_int = 0x4000;
    let mut result = 0;
    if flags & posix_protocol::OPEN_APPEND != 0 {
        result |= O_APPEND;
    }
    if flags & posix_protocol::OPEN_NONBLOCK != 0 {
        result |= O_NONBLOCK;
    }
    result
}

fn retry_open_with_prompt(path: *const c_char, flags: c_int, mode: c_int) -> Result<c_int, c_int> {
    retry_open_with_prompt_using(path, flags, || file_mutation::open(path, flags, mode))
}

fn retry_open_with_prompt_using(
    path: *const c_char,
    flags: c_int,
    retry: impl FnOnce() -> Result<c_int, c_int>,
) -> Result<c_int, c_int> {
    let path_bytes = unsafe { c_bytes(path) };
    let path_str = core::str::from_utf8(path_bytes).map_err(|_| EACCES)?;
    let capability = if open_requires_write_access(flags) {
        "fs.write.user"
    } else {
        "fs.read.user"
    };
    let decision = if request_persistent_capability(capability, Some(path_str), Some("file access"))
    {
        CapabilityDecision::AllowForProcess
    } else {
        request_capability_from_shell(capability, Some(path_str), Some("file access"))
            .unwrap_or(CapabilityDecision::Deny)
    };
    match decision {
        CapabilityDecision::AllowOnce
        | CapabilityDecision::AllowForProcess
        | CapabilityDecision::AllowPersistently
        | CapabilityDecision::AllowAllUserGrantable => {
            let result = retry();
            if decision == CapabilityDecision::AllowOnce {
                drop_capability(capability);
            }
            result
        }
        CapabilityDecision::Deny => Err(EACCES),
    }
}

struct RuntimeLaunchContext;

impl LaunchContextOps<FdObject> for RuntimeLaunchContext {
    type Error = c_int;

    fn get_value(&mut self, key: u64) -> Result<Option<u64>, Self::Error> {
        let mut value = 0u64;
        match syscall::raw_syscall2(
            syscall::SyscallNumber::LaunchValueGet,
            key,
            (&mut value as *mut u64) as u64,
        )
        .into_result()
        {
            Ok(_) => Ok(Some(value)),
            Err(error) if error.native_error() == Some(mnu_abi::status::Error::NotFound) => Ok(None),
            Err(error) => Err(map_kernel_errno(error.raw())),
        }
    }

    fn get_handle(&mut self, key: u64) -> Result<Option<FdObject>, Self::Error> {
        match syscall::raw_syscall1(
            syscall::SyscallNumber::LaunchHandleGet,
            key,
        )
        .into_result()
        {
            Ok(lower_handle) => Ok(Some(FdObject {
                lower_handle,
                kind: FdKind::Unused,
                open_flags: 0,
                close_owned: true,
            })),
            Err(error) if error.native_error() == Some(mnu_abi::status::Error::NotFound) => Ok(None),
            Err(error) => Err(map_kernel_errno(error.raw())),
        }
    }

    fn get_handle_rights(&mut self, handle: FdObject) -> Result<u64, Self::Error> {
        syscall_errno(syscall::raw_syscall1(
            syscall::SyscallNumber::HandleRightsGet,
            handle.lower_handle,
        ))
    }

    fn set_value(&mut self, key: u64, value: u64) -> Result<(), Self::Error> {
        syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::ContextValueSet,
            key,
            value,
        ))
        .map(|_| ())
    }

    fn remove_value(&mut self, key: u64) -> Result<(), Self::Error> {
        syscall_errno(syscall::raw_syscall1(
            syscall::SyscallNumber::ContextValueRemove,
            key,
        ))
        .map(|_| ())
    }

    fn set_handle(&mut self, key: u64, handle: FdObject) -> Result<(), Self::Error> {
        syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::ContextHandleSet,
            key,
            handle.lower_handle,
        ))
        .map(|_| ())
    }

    fn remove_handle(&mut self, key: u64) -> Result<(), Self::Error> {
        syscall_errno(syscall::raw_syscall1(
            syscall::SyscallNumber::ContextHandleRemove,
            key,
        ))
        .map(|_| ())
    }
}

fn map_launch_fd_error(error: LaunchFdError<c_int>) -> c_int {
    match error {
        LaunchFdError::Context(errno) => errno,
        LaunchFdError::InvalidDescriptor
        | LaunchFdError::InvalidMetadata
        | LaunchFdError::MissingHandle
        | LaunchFdError::UnexpectedHandle => EIO,
    }
}

fn restore_fd_state_from_launch_context(fds: &mut FdTable<FdObject>) -> Result<bool, c_int> {
    let mut context = RuntimeLaunchContext;
    let mut operations = RuntimeFdOps;
    let mut references = fd_lease::RestoreReferences::new();
    restore_launch_context(
        fds,
        MAX_FDS,
        &mut context,
        &mut operations,
        |metadata, attachment| {
            let kind = fd_kind_from_inherited(metadata.kind)?;
            let (lower_handle, close_owned) = attachment
                .map(|(object, _)| (object.lower_handle, true))
                .unwrap_or((0, false));
            let object = FdObject {
                lower_handle,
                kind,
                open_flags: metadata.open_flags as c_int,
                close_owned,
            };
            references.register(object).ok()?;
            Some(object)
        },
    )
    .map_err(map_launch_fd_error)
}

fn attach_fd_launch_context(
    fds: &FdTable<FdObject>,
    output: &mut [u8],
    length: usize,
) -> Result<usize, c_int> {
    use mnu_abi::process_image::ContextUpdate as U;
    let mut updates = [U {
        kind: U::REMOVE_VALUE,
        key: 0,
        value: 0,
    }; MAX_FDS * 2 + 1];
    let count = plan_launch_context(
        fds,
        MAX_FDS,
        &mut updates,
        |object| {
        Some(LaunchFdDescription {
            kind: inherited_fd_kind(object.kind)?,
            open_flags: object.open_flags as u32,
            has_handle: object.close_owned,
        })
        },
        |object| Some(object.lower_handle),
    )
    .map_err(|_| EIO)?;
    mnu_abi::process_image::attach_context(output, length, &updates[..count]).map_err(|_| EIO)
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
    let mut state = state();
    if state.initialized {
        return;
    }

    state.initialized = true;
    state.argv = stack.argv;
    state.envp = stack.envp;
    state.executable = stack.executable;
    match restore_fd_state_from_launch_context(&mut state.fds) {
        Ok(true) => {}
        Ok(false) => {
            let mut operations = RuntimeFdOps;
            let _ = state
                .fds
                .install_at(0, FdObject::stdio(FdKind::Stdin), &mut operations);
            let _ = state
                .fds
                .install_at(1, FdObject::stdio(FdKind::Stdout), &mut operations);
            let _ = state
                .fds
                .install_at(2, FdObject::stdio(FdKind::Stderr), &mut operations);
        }
        Err(error) => startup_failure(b"newlib: inherited FD restore failed: ", error),
    }

    let stack_limit = align_down(stack.stack_top, PAGE_SIZE).saturating_sub(PAGE_SIZE);
    state.heap = HeapState {
        initialized: true,
        // Exec supplies an already admitted initial arena. Other native
        // launches leave zero and acquire placement lazily through _sbrk().
        base: stack.initial_heap,
        current_break: stack.initial_heap,
        mapped_end: stack.initial_heap
            + if stack.initial_heap == 0 {
                0
            } else {
                mochios_posix_client::process_image::INITIAL_HEAP_BYTES as usize
            },
        reserved_end: stack.initial_heap
            + if stack.initial_heap == 0 {
                0
            } else {
                mochios_posix_client::process_image::INITIAL_HEAP_BYTES as usize
            },
        pending_release: None,
        maximum_end: stack_limit,
        page_size: PAGE_SIZE,
    };
    drop(state);

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
    let value = unsafe { malloc(core::mem::size_of::<PosixSpawnFileActions>()) }
        .cast::<PosixSpawnFileActions>();
    if value.is_null() {
        return Err(ENOMEM);
    }
    unsafe { init_file_actions_list(value) };
    Ok(value)
}

unsafe fn release_file_actions_object(target: *mut PosixSpawnFileActions) {
    unsafe { free(target.cast()) };
}

// The opaque handle slot belongs to the caller and need not be Rust-aligned.
// Its non-null value must still be an initialized, allocator-owned action list.
fn file_actions_object(
    actions: *const *mut PosixSpawnFileActions,
) -> Result<*mut PosixSpawnFileActions, c_int> {
    if actions.is_null() {
        return Err(EINVAL);
    }
    let mut bytes = [0; core::mem::size_of::<usize>()];
    user_copy::read(actions.cast(), &mut bytes)?;
    let object = usize::from_ne_bytes(bytes) as *mut PosixSpawnFileActions;
    if object.is_null() {
        Err(EINVAL)
    } else {
        Ok(object)
    }
}

unsafe fn allocate_file_action_entry() -> Result<*mut PosixSpawnFileActionsEntry, c_int> {
    let value = unsafe { malloc(core::mem::size_of::<PosixSpawnFileActionsEntry>()) }
        .cast::<PosixSpawnFileActionsEntry>();
    if value.is_null() {
        return Err(ENOMEM);
    }
    unsafe {
        value.write(PosixSpawnFileActionsEntry {
            fae_list: StailqEntry {
                stqe_next: ptr::null_mut(),
            },
            fae_action: 0,
            fae_fildes: 0,
            fae_data: PosixSpawnFileActionData { dirfd: 0 },
        });
    }
    Ok(value)
}

unsafe fn release_file_action_entry(target: *mut PosixSpawnFileActionsEntry) {
    unsafe { free(target.cast()) };
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

fn clone_current_fd_table() -> Result<(FdTable<FdObject>, [Option<fd_lease::Lease>; MAX_FDS]), c_int>
{
    let state = state();
    let mut leases = [const { None }; MAX_FDS];
    for (fd, lease) in leases.iter_mut().enumerate() {
        if let Some(entry) = state.fds.get(fd as c_int) {
            *lease = Some(fd_lease::Lease::new(entry)?);
        }
    }
    Ok((state.fds.clone(), leases))
}

fn close_fd_entry(fds: &mut FdTable<FdObject>, fd: c_int) -> Result<(), c_int> {
    let entry = fds.get(fd).ok_or(EBADF)?;
    fd_lease::retire(entry.handle)?;
    fds.take(fd).map_err(|_| EBADF)?;
    Ok(())
}

fn duplicate_fd_entry(
    fds: &mut FdTable<FdObject>,
    old_fd: c_int,
    new_fd: c_int,
    limit: c_int,
) -> Result<(), c_int> {
    if old_fd < 0 || new_fd < 0 || old_fd as usize >= MAX_FDS || new_fd as usize >= MAX_FDS {
        return Err(EBADF);
    }
    if old_fd != new_fd && new_fd >= limit {
        return Err(EBADF);
    }
    let mut operations = RuntimeFdOps;
    fds.duplicate_to(old_fd, new_fd, &mut operations)
        .map_err(map_fd_error)?;
    Ok(())
}

fn duplicate_spawn_fd_entry(old_fd: c_int, new_fd: c_int) -> Result<(), c_int> {
    if old_fd < 0 || new_fd < 0 || old_fd as usize >= MAX_FDS || new_fd as usize >= MAX_FDS {
        return Err(EBADF);
    }
    if old_fd != new_fd && new_fd >= process_fd_limit()? {
        return Err(EBADF);
    }
    let mut operations = RuntimeFdOps;
    state()
        .fds
        .duplicate_for_spawn(old_fd, new_fd, &mut operations)
        .map_err(map_fd_error)?;
    Ok(())
}

fn change_directory_path(path: *const c_char) -> Result<(), c_int> {
    path_io::chdir(path)
}

fn change_directory_entry(entry: FdEntry) -> Result<(), c_int> {
    if entry.handle.kind != FdKind::ObjectDirectory {
        return Err(ENOTDIR);
    }
    let client = posix_client().map_err(map_posix_client_error)?;
    client
        .fchdir(ObjectHandleAttachment {
            handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
            rights: entry.rights,
        })
        .map_err(map_posix_client_error)
}

fn duplicate_live_fd(old_fd: c_int, new_fd: c_int) -> Result<c_int, c_int> {
    with_fd_entry(old_fd)?;
    let limit = if old_fd == new_fd {
        MAX_FDS as c_int
    } else {
        process_fd_limit()?
    };
    let mut state = state();
    duplicate_fd_entry(&mut state.fds, old_fd, new_fd, limit)?;
    Ok(new_fd)
}

fn duplicate_fd_from(
    fds: &mut FdTable<FdObject>,
    fd: c_int,
    minimum: Option<c_int>,
    close_on_exec: bool,
    limit: c_int,
) -> Result<c_int, c_int> {
    // Validate the source before the range, as with other descriptor APIs.
    if fd < 0 || fd as usize >= MAX_FDS || fds.get(fd).is_none() {
        return Err(EBADF);
    }
    if minimum.is_some_and(|minimum| minimum < 0 || minimum >= limit) {
        return Err(EINVAL);
    }
    fds.duplicate_from(
        fd,
        minimum.unwrap_or(0),
        limit,
        close_on_exec,
        &mut RuntimeFdOps,
    )
    .map_err(|error| match error {
        FdError::InvalidDescriptor => EMFILE,
        other => map_fd_error(other),
    })
}

fn apply_spawn_file_actions(actions: &spawn_file_actions::Actions) -> Result<(), c_int> {
    use spawn_file_actions::Action;
    actions.apply(|action| {
        match action {
            Action::Close(fd) => {
                let mut operations = RuntimeFdOps;
                state().fds.close_for_spawn(*fd, &mut operations);
            }
            Action::Dup2 { source, target } => {
                duplicate_spawn_fd_entry(*source, *target)?;
            }
            Action::Open {
                fd,
                flags,
                mode,
                path,
            } => {
                if *fd < 0 || *fd >= process_fd_limit()? {
                    return Err(EBADF);
                }
                file_mutation::open_for_spawn(path.as_ptr(), *flags, *mode as c_int, *fd)?;
            }
            Action::Chdir(path) => {
                change_directory_path(path.as_ptr())?;
            }
            Action::Fchdir(fd) => {
                path_io::fchdir(*fd)?;
            }
        }
        Ok(())
    })
}

fn close_object_handle(handle: u32) {
    let _ = syscall_errno(syscall::raw_syscall1(
        syscall::SyscallNumber::HandleClose,
        u64::from(handle),
    ));
}

fn absolute_exec_identity(
    path: &[u8],
    output: &mut [u8; MAX_EXECUTABLE_PATH_LEN],
) -> Result<usize, c_int> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    if path[0] == b'/' {
        if path.len() >= output.len() {
            return Err(ENAMETOOLONG);
        }
        output[..path.len()].copy_from_slice(path);
        return Ok(path.len());
    }
    let client = posix_client().map_err(map_posix_client_error)?;
    let mut cwd = [0u8; posix_protocol::MAX_PATH_LEN];
    let cwd_length = client.getcwd(&mut cwd).map_err(map_posix_client_error)?;
    let separator = usize::from(cwd_length != 1);
    let length = cwd_length
        .checked_add(separator)
        .and_then(|length| length.checked_add(path.len()))
        .ok_or(ENAMETOOLONG)?;
    if length >= output.len() {
        return Err(ENAMETOOLONG);
    }
    output[..cwd_length].copy_from_slice(&cwd[..cwd_length]);
    let mut written = cwd_length;
    if separator != 0 {
        output[written] = b'/';
        written += 1;
    }
    output[written..length].copy_from_slice(path);
    Ok(length)
}

fn authorize_exec_path(path_bytes: &[u8]) -> Result<(), c_int> {
    if path_bytes.is_empty() || path_bytes[0] != b'/' {
        return Err(EINVAL);
    }
    if path_bytes.len() >= MAX_EXECUTABLE_PATH_LEN {
        return Err(ENAMETOOLONG);
    }
    let endpoint = syscall_errno(syscall::raw_syscall2(
        syscall::SyscallNumber::FindProcessByName,
        CAPABILITY_SERVICE_NAME.as_ptr() as u64,
        CAPABILITY_SERVICE_NAME.len() as u64,
    ))?;
    if endpoint == 0 {
        return Err(ENOENT);
    }
    let mut request = [0u8; core::mem::size_of::<u32>() + MAX_EXECUTABLE_PATH_LEN];
    request[..4].copy_from_slice(&AUTHORIZE_EXEC_OPCODE.to_le_bytes());
    request[4..4 + path_bytes.len()].copy_from_slice(path_bytes);
    let request_len = 4 + path_bytes.len();
    let mut reply = [0u8; 8];
    let message = syscall_errno(syscall::raw_syscall5(
        syscall::SyscallNumber::IpcCall,
        endpoint,
        request.as_ptr() as u64,
        request_len as u64,
        reply.as_mut_ptr() as u64,
        reply.len() as u64,
    ))?;
    if (message & 0xffff_ffff) as usize != reply.len() {
        return Err(EIO);
    }
    let status = u64::from_le_bytes(reply);
    if status == 0 {
        Ok(())
    } else {
        let status = i64::try_from(status).map_err(|_| EIO)?;
        Err(map_kernel_errno(status))
    }
}

fn authorize_clone_path(identity: &str) -> Result<(), c_int> {
    use mochios_capability_protocol::{
        RESOLVE_EXECUTION_SECURITY_OPCODE, decode_resolve_execution_security_reply,
    };
    if !identity.starts_with('/') || identity.len() >= MAX_EXECUTABLE_PATH_LEN {
        return Err(EINVAL);
    }
    let endpoint = syscall_errno(syscall::raw_syscall2(
        syscall::SyscallNumber::FindProcessByName,
        CAPABILITY_SERVICE_NAME.as_ptr() as u64,
        CAPABILITY_SERVICE_NAME.len() as u64,
    ))?;
    if endpoint == 0 {
        return Err(ENOENT);
    }
    let mut request = [0u8; 12 + MAX_EXECUTABLE_PATH_LEN];
    request[..4].copy_from_slice(&RESOLVE_EXECUTION_SECURITY_OPCODE.to_le_bytes());
    request[4..12].copy_from_slice(
        &mnu_abi::exec::ExecutionClass::Unprivileged
            .as_raw()
            .to_le_bytes(),
    );
    request[12..12 + identity.len()].copy_from_slice(identity.as_bytes());
    let mut response = [0u8; 8192];
    let result = syscall_errno(syscall::raw_syscall5(
        syscall::SyscallNumber::IpcCall,
        endpoint,
        request.as_ptr() as u64,
        (12 + identity.len()) as u64,
        response.as_mut_ptr() as u64,
        response.len() as u64,
    ))?;
    let length = (result & 0xffff_ffff) as usize;
    let response = response.get(..length).ok_or(EIO)?;
    let reply = decode_resolve_execution_security_reply(response).map_err(|_| EIO)?;
    if reply.status == 0 {
        Ok(())
    } else {
        let status = i64::try_from(reply.status).map_err(|_| EIO)?;
        Err(map_kernel_errno(status))
    }
}

fn replace_process_image(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
    fds: &FdTable<FdObject>,
) -> Result<(), c_int> {
    let mut inputs = exec_inputs::Inputs::new();
    inputs.capture(path, argv, envp)?;
    let path_bytes = inputs.path();
    let path_text = core::str::from_utf8(path_bytes).map_err(|_| EINVAL)?;
    let mut identity = [0u8; MAX_EXECUTABLE_PATH_LEN];
    let identity_length = absolute_exec_identity(path_bytes, &mut identity)?;
    let identity = &identity[..identity_length];
    let identity_text = core::str::from_utf8(identity).map_err(|_| EINVAL)?;
    let mut arguments = [&[][..]; MAX_EXEC_VECTOR_ENTRIES];
    let mut environment = [&[][..]; MAX_EXEC_VECTOR_ENTRIES];
    let (mut argument_count, environment_count) = inputs.vectors(&mut arguments, &mut environment);
    if argument_count == 0 {
        arguments[0] = path_bytes;
        argument_count = 1;
    }
    let mut random = [0u8; 16];
    let random_length = syscall_errno(syscall::raw_syscall2(
        syscall::SyscallNumber::RandomFill,
        random.as_mut_ptr() as u64,
        random.len() as u64,
    ))?;
    if random_length != random.len() as u64 {
        return Err(EIO);
    }
    let mut startup_image = [0u8; MAX_STARTUP_IMAGE_BYTES];
    let plan = image_startup::Plan::new(random)?;
    let startup_length = mochios_posix_client::process_image::encode_initial_stack_with_aux(
        &arguments[..argument_count],
        &environment[..environment_count],
        path_bytes,
        random,
        &plan.auxiliary(),
        &mut startup_image,
    )
    .map_err(|error| match error {
        mochios_posix_client::process_image::EncodeError::ImageTooLarge
        | mochios_posix_client::process_image::EncodeError::EmptyArgumentVector => E2BIG,
        mochios_posix_client::process_image::EncodeError::InvalidText => EINVAL,
        mochios_posix_client::process_image::EncodeError::Codec(_) => EIO,
    })?;
    let startup_length = mnu_abi::process_image::attach_mappings(
        &mut startup_image,
        startup_length,
        &plan.mappings(),
    )
    .map_err(|_| EIO)?;
    let startup_length = attach_fd_launch_context(fds, &mut startup_image, startup_length)?;

    let byte_ceiling = address_space::snapshot()?.byte_ceiling();
    let client = posix_client().map_err(map_posix_client_error)?;
    let opened = client
        .open_at(
            if path_bytes.first() == Some(&b'/') {
                OpenAtBase::ProcessRoot
            } else {
                OpenAtBase::ProcessCwd
            },
            posix_protocol::OPEN_READ | posix_protocol::OPEN_EXECUTE,
            0,
            path_text,
        )
        .map_err(map_posix_client_error)?;
    // Native image snapshots use bounded positional reads, never the shared
    // open-file cursor. Do not require unrelated SEEK authority here.
    let required_rights = syscall::HANDLE_RIGHT_READ;
    if opened.rights & required_rights != required_rights {
        close_object_handle(opened.handle);
        return Err(EACCES);
    }
    if let Err(error) = authorize_exec_path(identity) {
        close_object_handle(opened.handle);
        return Err(error);
    }
    let result = match syscall::image::replace_bounded(
        opened.handle,
        identity_text,
        &startup_image[..startup_length],
        byte_ceiling,
    ) {
        Ok(never) => match never {},
        Err(error) => Err(mochios_posix_client::image_error::errno(error.raw())),
    };
    close_object_handle(opened.handle);
    result
}

fn execve_with_launch_context(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> Result<(), c_int> {
    io_resources::with(|| Ok(()), |_| execve_with_launch_context_owned(path, argv, envp))
}

fn execve_with_launch_context_owned(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> Result<(), c_int> {
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let delivery = mochios_posix_client::upcall_guard::Guard::enter(&control.native_delivery_defer)
        .ok_or(EOVERFLOW)?;
    let captured = clone_current_fd_table()?;
    let mut scope = core::pin::pin!(callback_resources::Scope::new(
        &control.callback_resources,
        control.active_signal_scope_id.load(Ordering::Acquire),
        captured
    ));
    // Keep snapshot leases tracked if a signal abandons the exec preparation.
    unsafe { scope.as_mut().activate() };
    drop(delivery);
    let result = replace_process_image(
        path,
        argv,
        envp,
        &scope.as_ref().get_ref().resource().unwrap().0,
    );
    let _delivery =
        mochios_posix_client::upcall_guard::Guard::enter(&control.native_delivery_defer)
            .unwrap_or_else(|| process_exit(EOVERFLOW));
    unsafe { scope.as_mut().retire() };
    result
}

#[inline(never)]
fn clone_registered_process() -> Result<c_int, c_int> {
    spawn_resources::fork()
}

#[inline(never)]
fn clone_registered_process_owned(
    startup: &mut CloneStartup,
    policy: &mut Option<fork_policy::Preparation>,
    mut track_child: impl FnMut(Option<(u64, bool)>),
) -> Result<(u64, FdTable<FdObject>, Option<u32>), c_int> {
    // Finish endpoint initialization before cloning. Copying the once-cell in
    // its `initializing` state would leave the child waiting for a thread that
    // does not exist in the cloned process.
    let client = posix_client().map_err(map_posix_client_error)?;
    let (_, thread_control) = current_thread_control().ok_or(ENOTSUP)?;
    service_signal_mask(thread_control, posix_protocol::SIGNAL_MASK_QUERY, 0)?;
    // Captured as ordinary stream Handles, not FDs or kernel POSIX state.
    // Keep ownership until both sides have confirmed child runtime startup.
    // Do not snapshot a thread slot during publication/reclamation. Acquire
    // this before the allocator, which those operations may themselves use.
    let lifecycle_guard = thread_lifecycle::capture()?;
    let mut resource_guards = [const { None }; mochios_posix_client::thread::MAX_THREADS];
    for (index, other) in THREADS.iter().enumerate() {
        if !ptr::eq(other, thread_control) {
            resource_guards[index] = Some(other.callback_resources.capture_for_fork().ok_or(EAGAIN)?);
        }
    }
    let libc_guard = libc_lock::capture()?;
    // malloc can enter _sbrk and acquire STATE. Stabilize its arena first, not
    // after taking STATE, and retain the caller's existing recursion depth.
    let allocator_guard = atfork::freeze_allocator();
    // Heap growth may consult the shared resource page while malloc is held.
    // Discovery uses only fixed stack buffers/native mapping, never malloc.
    // Keep allocator -> POLICY -> STATE order, not POLICY -> allocator.
    let mut policy_guard = resource_policy::freeze_for_clone();
    // Lifecycle/resource/libc gates stabilize shared runtime state. A running
    // sibling's opaque private memory is retained in the child, never walked.
    // An unpublished startup still cannot provide a complete native binding.
    if THREADS.iter().any(|other| {
        !ptr::eq(other, thread_control)
            && other.state.load(Ordering::Acquire) == THREAD_STARTING
    }) {
        return Err(EAGAIN);
    }
    // Freeze only after the allocator, on the shared fork/spawn path. User
    // callbacks run outside this scope and registration allocates before it.
    let registry_guard = atfork::freeze_registry();
    // Acquire runtime-owned state in dependency order before STATE. Signal
    // disposition updates hold UPDATE before ACTIONS; endpoint initialization
    // may perform IPC but never runs while STATE is held. Both processes must
    // release these copied guards before rebuilding child upcall state.
    let socket_guard = socket_record::freeze_for_clone();
    let update_guard = SIGNAL_ACTION_UPDATE.lock();
    let actions_guard = SIGNAL_ACTIONS.lock();
    // Match copied handler state to service dispositions before capturing VM.
    // Prepare before STATE so error cleanup never performs IPC under that lock.
    // Publish the token into the outer callback owner while allocator_guard
    // still defers native delivery. Local stack Drop is not run when a C
    // handler abandons the registration/acknowledgement operation.
    let preparation = policy.insert(fork_policy::Preparation::new(client)?);
    // Keep the FD table stable across the address-space clone. Both parent and
    // child drop their private copy of this guard immediately after the native
    // clone returns, so the child never inherits a permanently locked STATE.
    let guard = state();
    // Handle captures include retired-but-pinned references too. Freeze their
    // bookkeeping with the FD table, and unlock the copied book in both images.
    let mut fd_borrows = fd_lease::BORROWS.lock();
    let inherited_fds = guard.fds.clone();
    if guard.executable.is_null() {
        return Err(ENOENT);
    }
    let identity = unsafe { c_bytes(guard.executable) };
    let identity = core::str::from_utf8(identity).map_err(|_| EINVAL)?;
    let mut capture = handle_capture::Capture::new()?;
    let mut records = [mnu_abi::HandleInfo::default(); mnu_abi::process_create::MAX_HANDLES];
    let count = capture.records(&mut records)?;
    // Private references and references owned only by disappearing operation
    // scopes have no child owner. Explicitly omit those labels; do not request
    // delegation rights or revive retired descriptor owners.
    let mut excluded = [0u32; mnu_abi::process_create::MAX_HANDLES];
    let mut excluded_count = 0;
    for record in &records[..count] {
        if fd_borrows.discarded_by_fork(u64::from(record.handle), newlib_lock_identity()) {
            excluded[excluded_count] = record.handle;
            excluded_count += 1;
        }
    }
    let mut grants = [mnu_abi::process_create::HandleGrant {
        key: 0,
        source: 0,
        target: 0,
        rights: 0,
    }; mnu_abi::process_create::MAX_HANDLES];
    let count = mochios_posix_client::inheritance::prepare(
        &records[..count],
        &excluded[..excluded_count],
        &mut grants,
    )
        .map_err(|error| match error {
            mochios_posix_client::inheritance::Error::NonTransferable(_) => EACCES,
            mochios_posix_client::inheritance::Error::TooManyHandles
            | mochios_posix_client::inheritance::Error::BufferTooSmall => EAGAIN,
            _ => EIO,
        })?;
    let control = syscall_errno(syscall::raw_syscall1(
        syscall::SyscallNumber::LaunchHandleGet,
        posix_protocol::CONTROL_HANDLE_KEY,
    ))?;
    let endpoint = grants[..count]
        .iter_mut()
        .find(|grant| u64::from(grant.source) == control)
        .ok_or(EBADF)?;
    endpoint.key = posix_protocol::CONTROL_HANDLE_KEY;
    let mut metadata = [0u8; mnu_abi::process_create::CAPTURE_HEADER_LEN
        + mnu_abi::process_create::MAX_IDENTITY_BYTES
        + mnu_abi::process_create::MAX_LABEL_BYTES
        + mnu_abi::process_create::CONTEXT_LEN
        + mnu_abi::process_create::MAX_HANDLES * mnu_abi::process_create::HANDLE_LEN];
    let mut context = syscall::ThreadCreateContext {
        entry: 1,
        stack_pointer: 16,
        ..Default::default()
    };
    // Validate metadata capacity and grants before creating a detached image.
    let length = mnu_abi::process_create::encode_context(
        identity,
        "fork-child",
        &context,
        &grants[..count],
        &[],
        &mut metadata,
    )
    .map_err(|_| EINVAL)?;
    mnu_abi::process_create::attach_handle_capture(&mut metadata, length, capture.handle())
        .map_err(|_| EINVAL)?;
    authorize_clone_path(identity)?;
    let libc_registry = libc_guard.freeze_registry();
    let image = unsafe {
        mochios_posix_client::snapshot::capture_native(
            &mut context,
            thread_control.thread_local_base.load(Ordering::Relaxed),
        )
    };
    drop(libc_registry);
    // Keep the captured image and Handle capture protected while releasing
    // the copied locks. The parent publishes its child owner before reopening
    // delivery; neither temporary reference is left on an abandonable stack.
    let creation_delivery = defer_native_delivery();
    if image == 0 {
        capture.disarm_child();
        preparation.disarm_child();
        resource_policy::reset_child(&mut policy_guard);
        if FORK_EPOCH
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            })
            .is_err()
        {
            startup.fail(EOVERFLOW);
        }
        // Rebind before releasing owner-tracked newlib locks: the copied
        // ThreadControl retains its private lock identity, not its native ID.
        thread_control.native_id.store(
            native_thread_id().unwrap_or_else(|error| startup.fail(map_kernel_errno(error.raw()))),
            Ordering::Relaxed,
        );
        // Only this thread resumes. Preserve its operation scopes, but do not
        // inherit foreign FD pins as permanent references with no destructor.
        // This is the child's private book; the parent's pins remain live.
        if fd_borrows
            .discard_for_fork(newlib_lock_identity(), |label| {
                // These references were intentionally never installed in the
                // child. Their old numeric slots may be reused by bootstrap.
                if excluded[..excluded_count].contains(&(label as u32)) {
                    return;
                }
                if let Err(error) = syscall_errno(syscall::raw_syscall1(
                    syscall::SyscallNumber::HandleClose,
                    label,
                )) {
                    startup.fail(error);
                }
            })
            .is_err()
        {
            startup.fail(EIO);
        }
    }
    drop(fd_borrows);
    drop(guard);
    drop(actions_guard);
    drop(update_guard);
    drop(socket_guard);
    drop(registry_guard);
    drop(policy_guard);
    drop(allocator_guard);
    drop(libc_guard);
    drop(resource_guards);
    drop(lifecycle_guard);
    if image == 0 {
        drop(creation_delivery);
        // Fork's numeric slot labels are temporary transfer metadata, not exec
        // inheritance policy. Keep only the selected control endpoint key;
        // later exec stages exactly its intended descriptors into context.
        if let Err(error) = mochios_posix_client::inheritance::clear_transient_context(
            &grants[..count],
            posix_protocol::CONTROL_HANDLE_KEY,
            |key| {
                syscall_errno(syscall::raw_syscall1(
                    syscall::SyscallNumber::ContextHandleRemove,
                    key,
                ))
                .map(|_| ())
            },
        ) {
            startup.fail(error);
        }
        state().fds.clear_reservations();
        state().timer_values.clear_for_fork();
        state().timer_cleanup = process_timer::CleanupBook::new();
        state().thread_clocks.clear_for_fork();
        // The new native thread has no copied upcall target.
        for other in &THREADS {
            if !ptr::eq(other, thread_control) && other.state.load(Ordering::Acquire) != THREAD_FREE
            {
                discard_fork_thread_control(other);
            }
        }
        let old_stack = thread_control.signal_upcall_stack.load(Ordering::Relaxed);
        let old_size = thread_control
            .signal_upcall_stack_size
            .load(Ordering::Relaxed);
        if let Err(error) = setup_signal_delivery(thread_control, None) {
            startup.fail(error);
        }
        if old_stack != 0
            && old_size != 0
            && !signal_delivery::stack_is_active(thread_control, old_stack, old_size)
        {
            let _ = syscall::raw_syscall2(
                syscall::SyscallNumber::MemoryUnmap,
                old_stack as u64,
                old_size as u64,
            );
        }
        startup.ready();
        return Ok((0, inherited_fds, None));
    }
    let image = u32::try_from(syscall_errno(syscall::RawSyscallResult::new(image))?)
        .map_err(|_| EOVERFLOW)?;
    // This guard ends before registration RPC or startup waiting.
    let created = (|| {
        let length = mnu_abi::process_create::encode_context(
            identity,
            "fork-child",
            &context,
            &grants[..count],
            &[],
            &mut metadata,
        )
        .map_err(|_| EINVAL)?;
        let length =
            mnu_abi::process_create::attach_handle_capture(&mut metadata, length, capture.handle())
                .map_err(|_| EINVAL)?;
        syscall_errno(syscall::raw_syscall3(
            syscall::SyscallNumber::ProcessCreate,
            u64::from(image),
            metadata.as_ptr() as u64,
            length as u64,
        ))
    })();
    close_object_handle(image);
    drop(capture);
    let handle = created?;
    track_child(Some((handle, false)));
    let handle = match u32::try_from(handle) {
        Ok(handle) => handle,
        Err(_) => {
            cleanup_failed_child(handle, false);
            track_child(None);
            return Err(EOVERFLOW);
        }
    };
    drop(creation_delivery);
    let mut registration_attempted = false;
    let result = (|| {
        let mut status = syscall::ProcessStatus::default();
        syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::ProcessHandleStatus,
            u64::from(handle),
            (&mut status as *mut syscall::ProcessStatus) as u64,
        ))?;
        let process_id = status.process_id;
        c_int::try_from(process_id).map_err(|_| EOVERFLOW)?;
        {
            let _delivery = defer_native_delivery();
            registration_attempted = true;
            track_child(Some((u64::from(handle), true)));
        }
        preparation.commit(ObjectHandleAttachment {
            handle,
            rights: syscall::HANDLE_RIGHT_WAIT | syscall::HANDLE_RIGHT_SIGNAL,
        })?;
        syscall_errno(syscall::raw_syscall1(
            syscall::SyscallNumber::ProcessHandleResume,
            u64::from(handle),
        ))?;
        // Locks copied by the VM snapshot were released before ProcessCreate.
        // EOF alone is failure: a child killed during startup is not ready.
        startup.wait()?;
        Ok(process_id)
    })();
    match result {
        Ok(process_id) => Ok((process_id, inherited_fds, Some(handle))),
        Err(error) => {
            let _delivery = defer_native_delivery();
            cleanup_failed_child(u64::from(handle), registration_attempted);
            track_child(None);
            Err(error)
        }
    }
}

struct CloneStartup {
    read: Option<u32>,
    write: Option<u32>,
}

impl CloneStartup {
    fn new() -> Result<Self, c_int> {
        let pair = create_spawn_status_stream()?;
        Ok(Self {
            read: Some(pair.read),
            write: Some(pair.write),
        })
    }

    fn send(&mut self, status: c_int) -> Result<(), c_int> {
        {
            let _delivery = defer_native_delivery();
            if let Some(handle) = self.read.take() {
                close_object_handle(handle);
            }
        }
        let handle = self.write.ok_or(EBADF)?;
        let result = child_startup::send(status, |packet| {
            syscall_errno(syscall::raw_syscall3(
                syscall::SyscallNumber::HandleWrite,
                u64::from(handle),
                packet.as_ptr() as u64,
                packet.len() as u64,
            ))
            .and_then(|count| usize::try_from(count).map_err(|_| EIO))
        });
        let _delivery = defer_native_delivery();
        if let Some(handle) = self.write.take() {
            close_object_handle(handle);
        }
        result
    }

    fn fail(&mut self, error: c_int) -> ! {
        let _ = self.send(error);
        process_exit(SPAWN_FAIL_EXIT_STATUS)
    }

    fn ready(&mut self) {
        if self.send(0).is_err() {
            process_exit(SPAWN_FAIL_EXIT_STATUS);
        }
    }

    fn wait(&mut self) -> Result<(), c_int> {
        {
            let _delivery = defer_native_delivery();
            if let Some(handle) = self.write.take() {
                close_object_handle(handle);
            }
        }
        let handle = self.read.ok_or(EBADF)?;
        let result = child_startup::receive(|packet| {
            syscall_errno(syscall::raw_syscall3(
                syscall::SyscallNumber::HandleRead,
                u64::from(handle),
                packet.as_mut_ptr() as u64,
                packet.len() as u64,
            ))
            .and_then(|count| usize::try_from(count).map_err(|_| EIO))
        });
        let _delivery = defer_native_delivery();
        if let Some(handle) = self.read.take() {
            close_object_handle(handle);
        }
        result
    }
}

impl Drop for CloneStartup {
    fn drop(&mut self) {
        let _delivery = defer_native_delivery();
        for handle in [self.read.take(), self.write.take()].into_iter().flatten() {
            close_object_handle(handle);
        }
    }
}

fn create_spawn_status_stream() -> Result<syscall::StreamPair, c_int> {
    let mut pair = syscall::StreamPair::default();
    syscall_errno(syscall::raw_syscall1(
        syscall::SyscallNumber::StreamPairCreate,
        (&mut pair as *mut syscall::StreamPair) as u64,
    ))?;
    Ok(pair)
}

fn report_spawn_error(handle: u32, errno_value: c_int) -> ! {
    let packet = errno_value.to_ne_bytes();
    let mut written = 0usize;
    while written < packet.len() {
        let result = syscall_errno(syscall::raw_syscall3(
            syscall::SyscallNumber::HandleWrite,
            u64::from(handle),
            packet[written..].as_ptr() as u64,
            (packet.len() - written) as u64,
        ));
        match result.and_then(|length| usize::try_from(length).map_err(|_| EIO)) {
            Ok(0) | Err(_) => break,
            Ok(length) => written += length,
        }
    }
    close_object_handle(handle);
    process_exit(SPAWN_FAIL_EXIT_STATUS)
}

fn read_spawn_status(handle: u32) -> Result<mochios_posix_client::spawn::ExecStatus, c_int> {
    let mut packet = [0u8; mochios_posix_client::spawn::EXEC_ERROR_PACKET_LEN];
    let mut length = 0usize;
    loop {
        let read = syscall_errno(syscall::raw_syscall3(
            syscall::SyscallNumber::HandleRead,
            u64::from(handle),
            packet[length..].as_mut_ptr() as u64,
            (packet.len() - length) as u64,
        ))
        .and_then(|read| usize::try_from(read).map_err(|_| EIO))?;
        let end_of_stream = read == 0;
        length += read;
        match mochios_posix_client::spawn::decode_exec_status(&packet[..length], end_of_stream) {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(_) => return Err(EIO),
        }
    }
}

struct FailedChildBackend;

impl child_cleanup::Backend for FailedChildBackend {
    fn is_exited(&mut self, handle: u64) -> Result<bool, c_int> {
        let mut status = syscall::ProcessStatus::default();
        syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::ProcessHandleStatus,
            handle,
            (&mut status as *mut syscall::ProcessStatus) as u64,
        ))?;
        Ok(status.state == syscall::PROCESS_STATE_EXITED)
    }

    fn terminate(&mut self, handle: u64) -> Result<(), c_int> {
        syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::ProcessHandleTerminate,
            handle,
            SPAWN_FAIL_EXIT_STATUS as u64,
        ))
        .map(|_| ())
    }

    fn reclaim_registration(&mut self, handle: u64) -> Result<(), c_int> {
        let handle = u32::try_from(handle).map_err(|_| EOVERFLOW)?;
        posix_client()
            .map_err(map_posix_client_error)?
            .abort_launched_child(ObjectHandleAttachment {
                handle,
                rights: syscall::HANDLE_RIGHT_WAIT,
            })
            .map_err(map_posix_client_error)
    }

    fn close(&mut self, handle: u64) -> Result<(), c_int> {
        syscall_errno(syscall::raw_syscall1(syscall::SyscallNumber::HandleClose, handle))
            .map(|_| ())
    }
}

fn cleanup_failed_child(handle: u64, registration_attempted: bool) {
    let mut cleanup = child_cleanup::Cleanup::new(handle, registration_attempted);
    let mut reported_failure = false;
    // Do not return the failed creation while its cleanup is unresolved. This
    // stack frame retains the exact owner even across interrupted syscalls or
    // failed IPC replies; no fixed retry count may turn failure into a leak.
    while let Err(error) = cleanup.retry(&mut FailedChildBackend) {
        if error != EAGAIN && error != EINTR && !reported_failure {
            let message = b"newlib: child cleanup pending; retaining ProcessHandle for retry\n";
            let _ = syscall::raw_syscall2(
                syscall::SyscallNumber::DebugWrite,
                message.as_ptr() as u64,
                message.len() as u64,
            );
            reported_failure = true;
        }
        // Sleep only spaces retries; its failure cannot advance cleanup.
        if syscall_errno(syscall::raw_syscall1(syscall::SyscallNumber::Sleep, 10)).is_err() {
            let _ = syscall::raw_syscall0(syscall::SyscallNumber::ThreadYield);
        }
    }
}

fn apply_spawn_attributes(attributes: Option<PosixSpawnAttr>) -> Result<(), c_int> {
    let Some(attributes) = attributes else {
        return Ok(());
    };
    let flags = attributes.sa_flags;
    if flags & mochios_posix_client::spawn::SET_PROCESS_GROUP != 0 {
        posix_client()
            .map_err(map_posix_client_error)?
            .set_process_group(0, i64::from(attributes.sa_pgroup))
            .map_err(map_posix_client_error)?;
    }
    if flags & mochios_posix_client::spawn::RESET_IDS != 0 {
        posix_client()
            .map_err(map_posix_client_error)?
            .reset_effective_ids()
            .map_err(map_posix_client_error)?;
    }
    if flags & mochios_posix_client::spawn::SET_SIGNAL_MASK != 0 {
        let (_, control) = register_current_thread().ok_or(EAGAIN)?;
        service_signal_mask(control, posix_protocol::SIGNAL_MASK_SET, attributes.sa_sigmask)?;
    }
    if flags & mochios_posix_client::spawn::SET_SIGNAL_DEFAULTS != 0 {
        let default = SignalAction::default_action();
        for signal in 1..=posix_protocol::SIGNAL_MAX {
            let bit = mochios_posix_client::signal::signal_bit(signal).unwrap_or(0);
            if attributes.sa_sigdefault & bit != 0
                && mochios_posix_client::signal::can_change_disposition(signal)
            {
                if unsafe { sigaction(signal as c_int, &default, ptr::null_mut()) } != 0 {
                    return Err(unsafe { *__errno() });
                }
            }
        }
    }
    Ok(())
}

fn with_fd_entry(fd: c_int) -> Result<fd_lease::Lease, c_int> {
    if fd < 0 || fd as usize >= MAX_FDS {
        return Err(EBADF);
    }
    let state = state();
    fd_lease::Lease::new(state.fds.get(fd).ok_or(EBADF)?)
}

fn terminal_attributes_from_newlib(termios: NewlibTermios) -> posix_protocol::TerminalAttributes {
    posix_protocol::TerminalAttributes {
        input_flags: termios.c_iflag,
        output_flags: termios.c_oflag,
        control_flags: termios.c_cflag,
        local_flags: termios.c_lflag,
        control_characters: termios.c_cc,
        input_speed: termios.c_ispeed,
        output_speed: termios.c_ospeed,
    }
}

fn terminal_attributes_to_newlib(attributes: posix_protocol::TerminalAttributes) -> NewlibTermios {
    NewlibTermios {
        c_iflag: attributes.input_flags,
        c_oflag: attributes.output_flags,
        c_cflag: attributes.control_flags,
        c_lflag: attributes.local_flags,
        c_cc: attributes.control_characters,
        c_ispeed: attributes.input_speed,
        c_ospeed: attributes.output_speed,
    }
}

fn retry_terminal_operation<T>(
    signal: u32,
    operation: impl FnMut() -> Result<T, c_int>,
) -> Result<T, c_int> {
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    mochios_posix_client::signal::terminal_operation(
        operation,
        drain_terminal_signals,
        || {
            (
                control.nonrestart_signal_generation.load(Ordering::Acquire),
                JOB_STOP_GENERATION.load(Ordering::Acquire),
                control.restart_signal_generation.load(Ordering::Acquire),
            )
        },
        // Native handle/IPC mechanisms do not synthesize EINTR. On these PTY
        // paths it is the authenticated POSIX backend's job-control response.
        // Its signal can already be dequeued for another thread whose upcall
        // has not started yet; its still-default disposition requires retry.
        || SIGNAL_ACTIONS.lock()[signal as usize - 1].handler == 0,
    )
}

fn drain_terminal_signals() -> Result<(), c_int> {
    drain_pending_signals()?;
    loop {
        let active = JOB_STOPS_IN_FLIGHT.load(Ordering::Acquire);
        if active == 0 {
            return Ok(());
        }
        // Another thread can receive the group signal. Resume may schedule
        // this caller before that thread publishes its stop-report outcome.
        mochios_posix_client::synchronization::wait_u32(
            &JOB_STOPS_IN_FLIGHT,
            active,
            mnu_abi::ADDRESS_WAIT_INFINITE,
        )
        .map_err(|error| map_kernel_errno(error.raw()))?;
    }
}

fn terminal_control(
    entry: FdEntry,
    control_code: u64,
    input: &[u8],
    output: &mut [u8],
) -> Result<usize, c_int> {
    if !matches!(
        entry.handle.kind,
        FdKind::ObjectPty | FdKind::ObjectSpecial | FdKind::ObjectTerminalFile
    ) {
        return Err(ENOTTY);
    }
    let length = retry_terminal_operation(posix_protocol::SIGNAL_TTOU, || {
        syscall_errno(syscall::raw_syscall6(
            syscall::SyscallNumber::HandleControl,
            entry.handle.lower_handle,
            control_code,
            input.as_ptr() as u64,
            input.len() as u64,
            output.as_mut_ptr() as u64,
            output.len() as u64,
        ))
    })
    .map_err(|error| match error {
        ENOTSUP | ENOSYS if entry.handle.kind == FdKind::ObjectSpecial => ENOTTY,
        error => error,
    })?;
    usize::try_from(length).map_err(|_| EOVERFLOW)
}

fn terminal_attributes(entry: FdEntry) -> Result<posix_protocol::TerminalAttributes, c_int> {
    let mut encoded = [0; posix_protocol::TERMINAL_ATTRIBUTES_LEN];
    let length = terminal_control(
        entry,
        posix_protocol::PTY_CONTROL_GET_ATTRIBUTES,
        &[],
        &mut encoded,
    )?;
    if length != encoded.len() {
        return Err(EIO);
    }
    posix_protocol::decode_terminal_attributes(&encoded).map_err(|_| EIO)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcgetwinsize(fd: c_int, size: *mut NewlibWinSize) -> c_int {
    if size.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            let mut bytes = [0; posix_protocol::TERMINAL_WINDOW_SIZE_LEN];
            let length = terminal_control(
                **entry,
                posix_protocol::PTY_CONTROL_GET_WINDOW_SIZE,
                &[],
                &mut bytes,
            )?;
            if length != bytes.len() {
                return Err(EIO);
            }
            let window = posix_protocol::decode_terminal_window_size(&bytes).map_err(|_| EIO)?;
            terminal_memory::write_window(
                size,
                NewlibWinSize {
                    ws_row: window.rows,
                    ws_col: window.columns,
                    ws_xpixel: window.pixel_width,
                    ws_ypixel: window.pixel_height,
                },
            )?;
            Ok(0)
        },
    );
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcsetwinsize(fd: c_int, size: *const NewlibWinSize) -> c_int {
    if size.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = io_resources::with_initialized(
        || Ok((with_fd_entry(fd)?, None)),
        |(_, window)| {
            *window = Some(terminal_memory::read_window(size)?);
            Ok(())
        },
        |(entry, window)| {
            set_terminal_window_size(**entry, window.unwrap())?;
            Ok(0)
        },
    );
    result_with_errno(result, -1)
}

fn set_terminal_window_size(entry: FdEntry, window: NewlibWinSize) -> Result<(), c_int> {
    let mut bytes = [0; posix_protocol::TERMINAL_WINDOW_SIZE_LEN];
    posix_protocol::encode_terminal_window_size(
        posix_protocol::TerminalWindowSize {
            rows: window.ws_row,
            columns: window.ws_col,
            pixel_width: window.ws_xpixel,
            pixel_height: window.ws_ypixel,
        },
        &mut bytes,
    )
    .map_err(|_| EINVAL)?;
    let length = terminal_control(
        entry,
        posix_protocol::PTY_CONTROL_SET_WINDOW_SIZE,
        &bytes,
        &mut [],
    )?;
    if length != 0 {
        return Err(EIO);
    }
    Ok(())
}

fn terminal_attachment(fd: c_int) -> Result<(fd_lease::Lease, ObjectHandleAttachment<u32>), c_int> {
    let entry = with_fd_entry(fd)?;
    if !matches!(
        entry.handle.kind,
        FdKind::ObjectPty | FdKind::ObjectSpecial | FdKind::ObjectTerminalFile
    ) {
        return Err(ENOTTY);
    }
    if entry.rights & syscall::HANDLE_RIGHT_TRANSFER == 0 {
        return Err(EACCES);
    }
    let attachment = ObjectHandleAttachment {
        handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
        rights: syscall::HANDLE_RIGHT_TRANSFER,
    };
    Ok((entry, attachment))
}

fn set_terminal_attributes(
    entry: FdEntry,
    action: c_int,
    termios: NewlibTermios,
) -> Result<(), c_int> {
    let control_code = match action {
        TCSANOW => posix_protocol::PTY_CONTROL_SET_ATTRIBUTES_NOW,
        TCSADRAIN => posix_protocol::PTY_CONTROL_SET_ATTRIBUTES_DRAIN,
        TCSAFLUSH => posix_protocol::PTY_CONTROL_SET_ATTRIBUTES_FLUSH,
        _ => return Err(EINVAL),
    };
    let mut encoded = [0; posix_protocol::TERMINAL_ATTRIBUTES_LEN];
    posix_protocol::encode_terminal_attributes(
        terminal_attributes_from_newlib(termios),
        &mut encoded,
    )
    .map_err(|_| EINVAL)?;
    loop {
        match terminal_control(entry, control_code, &encoded, &mut []) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(EIO),
            Err(EAGAIN) if action == TCSADRAIN || action == TCSAFLUSH => {
                let _ = wait_for_handle(
                    entry,
                    syscall::HANDLE_SIGNAL_IDLE | syscall::HANDLE_SIGNAL_PEER_CLOSED,
                )?;
            }
            Err(errno) => return Err(errno),
        }
    }
}

fn allocate_object_fd(
    handle: u32,
    rights: u64,
    kind: FdKind,
    flags: c_int,
) -> Result<c_int, c_int> {
    allocate_fd_entry(u64::from(handle), rights, kind, flags)
}

fn allocate_fd_entry(
    lower_handle: u64,
    rights: u64,
    kind: FdKind,
    flags: c_int,
) -> Result<c_int, c_int> {
    let limit = process_fd_limit()?;
    let mut state = state();
    state
        .fds
        .install_from(0, limit, object_entry(lower_handle, rights, kind, flags))
        .map_err(|_| EMFILE)
}

fn handle_is_nonblocking(entry: FdEntry) -> Result<bool, c_int> {
    if entry.handle.kind.is_socket() {
        return Ok(socket::get_status_flags(entry)? & O_NONBLOCK != 0);
    }
    let options = syscall_errno(syscall::raw_syscall1(
        syscall::SyscallNumber::HandleOptionsGet,
        entry.handle.lower_handle,
    ))?;
    Ok(options & syscall::HANDLE_OPTION_NONBLOCKING != 0)
}

fn wait_for_handle(entry: FdEntry, interests: u64) -> Result<u64, c_int> {
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let caught = control.nonrestart_signal_generation.load(Ordering::Acquire);
    wait_for_handle_since(entry, interests, control, caught)
}

fn wait_for_handle_since(
    entry: FdEntry,
    interests: u64,
    control: &ThreadControl,
    caught: u64,
) -> Result<u64, c_int> {
    wait_for_handle_capacity(
        entry,
        interests,
        control,
        caught,
        0,
        syscall::HANDLE_WAIT_INFINITE,
    )
}

fn wait_for_handle_capacity(
    entry: FdEntry,
    interests: u64,
    control: &ThreadControl,
    caught: u64,
    minimum_write_bytes: u32,
    deadline: u64,
) -> Result<u64, c_int> {
    let mut item = syscall::HandleWaitItem {
        handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
        minimum_write_bytes,
        interests,
        observed: 0,
    };
    mochios_posix_client::multiplex::wait_cancellable(
        caught,
        || control.nonrestart_signal_generation.load(Ordering::Acquire),
        || io_cancellation_requested(control),
        || control.multiplex_generation.load(Ordering::Acquire),
        |notification| {
            let guard = mnu_abi::HandleWaitGuard {
                address: (&control.multiplex_generation as *const AtomicU64) as u64,
                expected: notification,
            };
            match syscall_errno(syscall::raw_syscall4(
                syscall::SyscallNumber::HandleWaitManyGuarded,
                (&mut item as *mut syscall::HandleWaitItem) as u64,
                1,
                deadline,
                (&guard as *const mnu_abi::HandleWaitGuard) as u64,
            )) {
                Ok(_) => Ok(true),
                Err(EAGAIN) => Ok(false),
                Err(error) => Err(error),
            }
        },
        || {
            if deadline == syscall::HANDLE_WAIT_INFINITE {
                Ok(false)
            } else {
                monotonic_nanoseconds().map(|now| now >= deadline)
            }
        },
    )
    .map_err(|error| match error {
        mochios_posix_client::multiplex::WaitError::Interrupted
        | mochios_posix_client::multiplex::WaitError::Cancelled => EINTR,
        mochios_posix_client::multiplex::WaitError::Io(error) => error,
    })?;
    if item.observed == 0 && deadline != syscall::HANDLE_WAIT_INFINITE {
        Err(EAGAIN)
    } else {
        Ok(item.observed)
    }
}

fn stream_io<T>(
    entry: FdEntry,
    interests: u64,
    operation: impl FnMut() -> Result<T, c_int>,
) -> Result<T, c_int> {
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let caught = control.nonrestart_signal_generation.load(Ordering::Acquire);
    stream_io_since(entry, interests, control, caught, 0, operation)
}

fn stream_io_since<T>(
    entry: FdEntry,
    interests: u64,
    control: &ThreadControl,
    caught: u64,
    minimum_write_bytes: u32,
    operation: impl FnMut() -> Result<T, c_int>,
) -> Result<T, c_int> {
    stream_io_since_mode(
        entry,
        interests,
        control,
        caught,
        minimum_write_bytes,
        false,
        operation,
    )
}

fn stream_io_since_mode<T>(
    entry: FdEntry,
    interests: u64,
    control: &ThreadControl,
    caught: u64,
    minimum_write_bytes: u32,
    force_nonblocking: bool,
    operation: impl FnMut() -> Result<T, c_int>,
) -> Result<T, c_int> {
    let mut wait = socket::SocketWait::new(entry, interests)?;
    stream_io_since_wait(
        entry,
        interests,
        control,
        caught,
        minimum_write_bytes,
        force_nonblocking,
        &mut wait,
        operation,
    )
}

fn stream_io_since_wait<T>(
    entry: FdEntry,
    interests: u64,
    control: &ThreadControl,
    caught: u64,
    minimum_write_bytes: u32,
    force_nonblocking: bool,
    wait: &mut socket::SocketWait,
    mut operation: impl FnMut() -> Result<T, c_int>,
) -> Result<T, c_int> {
    loop {
        if io_cancellation_requested(control) {
            // Return through callers so partial writes and owned temporary
            // buffers are resolved before the public API cancels this thread.
            return Err(EINTR);
        }
        if control.nonrestart_signal_generation.load(Ordering::Acquire) != caught {
            return Err(EINTR);
        }
        match operation() {
            Err(EAGAIN) if !force_nonblocking && !handle_is_nonblocking(entry)? => {
                // Preserve the generation from before the attempt, including
                // across retries and successful prefixes of a large write.
                wait_for_handle_capacity(
                    entry,
                    interests,
                    control,
                    caught,
                    minimum_write_bytes,
                    wait.deadline(entry)?,
                )?;
            }
            result => return result,
        }
    }
}

fn io_cancellation_requested(control: &ThreadControl) -> bool {
    control.cancel_pending.load(Ordering::Acquire) != 0
        && (control.cancel_state.load(Ordering::Acquire) == PTHREAD_CANCEL_ENABLE
            || control.stdio_scope.permits_interrupt())
}

fn record_stdio_io(result: &Result<isize, c_int>) {
    let Some((_, control)) = current_thread_control() else {
        return;
    };
    match result {
        Ok(count) if *count > 0 => control.stdio_scope.note_progress(),
        Err(EINTR) if io_cancellation_requested(control) => control.stdio_scope.note_interruption(),
        _ => {}
    }
}

/// Internal newlib hook, called after cancellation is disabled but before a
/// FILE/list lock is acquired. No kernel or IPC ABI knows about this scope.
#[unsafe(no_mangle)]
pub extern "C" fn __mochios_stdio_cancel_enter(previous: c_int) {
    let (_, control) = current_thread_control().unwrap_or_else(|| process_exit(127));
    if !control
        .stdio_scope
        .enter(previous as u32 == PTHREAD_CANCEL_ENABLE)
    {
        process_exit(127);
    }
}

/// Called only after newlib unlocks and restores the previous cancel state.
#[unsafe(no_mangle)]
pub extern "C" fn __mochios_stdio_cancel_leave() {
    let (_, control) = current_thread_control().unwrap_or_else(|| process_exit(127));
    match control.stdio_scope.leave() {
        Some(true) => pthread_testcancel(),
        Some(false) => {}
        None => process_exit(127),
    }
}

fn syscall_write(entry: FdEntry, buffer: *const c_void, length: usize) -> Result<isize, c_int> {
    if entry.handle.kind.is_socket() {
        return socket::message_entry(entry, buffer as u64, length, 0, true);
    }
    if matches!(entry.handle.kind, FdKind::ObjectFile | FdKind::ObjectSpecial | FdKind::ObjectTerminalFile | FdKind::ObjectSharedMemory)
        && !mochios_posix_client::fd::access_allows_write(entry.handle.open_flags as u32)
    {
        return Err(EBADF);
    }
    if length == 0 {
        return Ok(0);
    }
    let written = match entry.handle.kind {
        FdKind::Stdout | FdKind::Stderr => syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::DebugWrite,
            buffer as u64,
            length as u64,
        ))?,
        FdKind::ObjectStreamWrite => {
            let (_, control) = register_current_thread().ok_or(EAGAIN)?;
            let caught = control.nonrestart_signal_generation.load(Ordering::Acquire);
            return mochios_posix_client::stream::write(
                length,
                handle_is_nonblocking(entry)?,
                |offset, remaining, complete| {
                    let flags = if complete {
                        mnu_abi::STREAM_WRITE_COMPLETE
                    } else {
                        0
                    };
                    let result = stream_io_since(
                        entry,
                        syscall::HANDLE_SIGNAL_WRITABLE | syscall::HANDLE_SIGNAL_PEER_CLOSED,
                        control,
                        caught,
                        if complete {
                            u32::try_from(remaining).map_err(|_| EOVERFLOW)?
                        } else {
                            1
                        },
                        || syscall_errno(syscall::raw_syscall4(
                            syscall::SyscallNumber::StreamWrite,
                            entry.handle.lower_handle,
                            buffer as u64 + offset as u64,
                            remaining as u64,
                            flags | mnu_abi::STREAM_IO_TRY,
                        )),
                    );
                    if matches!(result, Err(EPIPE)) {
                        // Signal dispatch can perform IPC and invoke handlers.
                        // Its preparation is not part of the FD-only stream wait.
                        io_resources::with(
                            || Ok(()),
                            |_| generate_thread_signal(posix_protocol::SIGNAL_PIPE),
                        )?;
                    }
                    result.and_then(|count| usize::try_from(count).map_err(|_| EIO))
                },
            )
            .map(|count| count as isize)
            .map_err(|error| match error {
                mochios_posix_client::stream::WriteError::InvalidResult => EIO,
                mochios_posix_client::stream::WriteError::Io(errno) => errno,
            });
        }
        FdKind::ObjectFile | FdKind::ObjectSharedMemory => {
            let limit = resource_policy::read(posix_protocol::RLIMIT_FSIZE)?;
            let result = if limit.soft == posix_protocol::RLIM_INFINITY {
                syscall::raw_syscall3(
                    syscall::SyscallNumber::HandleWrite,
                    entry.handle.lower_handle,
                    buffer as u64,
                    length as u64,
                )
            } else {
                syscall::raw_syscall4(
                    syscall::SyscallNumber::HandleWriteBounded,
                    entry.handle.lower_handle,
                    buffer as u64,
                    length as u64,
                    limit.soft,
                )
            };
            if limit.soft != posix_protocol::RLIM_INFINITY
                && result.raw() == mnu_abi::provider::STATUS_BOUND_REACHED as u64
            {
                generate_thread_signal(posix_protocol::SIGNAL_XFSZ)?;
                return Err(EFBIG);
            }
            syscall_errno(result)?
        }
        FdKind::ObjectSpecial => syscall_errno(syscall::raw_syscall3(
            syscall::SyscallNumber::HandleWrite,
            entry.handle.lower_handle,
            buffer as u64,
            length as u64,
        ))?,
        FdKind::ObjectPty | FdKind::ObjectTerminalFile => loop {
            match retry_terminal_operation(posix_protocol::SIGNAL_TTOU, || {
                syscall_errno(syscall::raw_syscall3(
                    syscall::SyscallNumber::HandleWrite,
                    entry.handle.lower_handle,
                    buffer as u64,
                    length as u64,
                ))
            }) {
                Ok(written) => break written,
                Err(EAGAIN) if !handle_is_nonblocking(entry)? => {
                    let _ = wait_for_handle(
                        entry,
                        syscall::HANDLE_SIGNAL_WRITABLE | syscall::HANDLE_SIGNAL_PEER_CLOSED,
                    )?;
                }
                Err(errno) => return Err(errno),
            }
        },
        FdKind::ObjectStreamRead => return Err(EBADF),
        FdKind::ObjectDirectory => return Err(EISDIR),
        _ => return Err(EBADF),
    };
    Ok(written as isize)
}

fn syscall_read(entry: FdEntry, buffer: *mut c_void, length: usize) -> Result<isize, c_int> {
    if matches!(entry.handle.kind, FdKind::ObjectFile | FdKind::ObjectSpecial | FdKind::ObjectTerminalFile | FdKind::ObjectSharedMemory)
        && !mochios_posix_client::fd::access_allows_read(entry.handle.open_flags as u32)
    {
        return Err(EBADF);
    }
    if length == 0 {
        return Ok(0);
    }
    if entry.handle.kind.is_socket() {
        return socket::message_entry(entry, buffer as u64, length, 0, false);
    }
    let read = match entry.handle.kind {
        FdKind::Stdin => return Err(EBADF),
        FdKind::ObjectFile | FdKind::ObjectSpecial | FdKind::ObjectSharedMemory => syscall_errno(syscall::raw_syscall3(
            syscall::SyscallNumber::HandleRead,
            entry.handle.lower_handle,
            buffer as u64,
            length as u64,
        ))?,
        FdKind::ObjectStreamRead => stream_io(
            entry,
            syscall::HANDLE_SIGNAL_READABLE | syscall::HANDLE_SIGNAL_PEER_CLOSED,
            || syscall_errno(syscall::raw_syscall4(
                syscall::SyscallNumber::StreamRead,
                entry.handle.lower_handle,
                buffer as u64,
                length as u64,
                mnu_abi::STREAM_IO_TRY,
            )),
        )?,
        FdKind::ObjectPty | FdKind::ObjectTerminalFile => {
            return terminal_read::read(entry, buffer, length);
        }
        FdKind::ObjectStreamWrite => return Err(EBADF),
        FdKind::ObjectDirectory => return Err(EISDIR),
        _ => return Err(EBADF),
    };
    Ok(read as isize)
}

fn refill_dir_stream(stream: &mut DirStream) -> Result<bool, c_int> {
    directory_io::refill(stream)
}

fn next_dirent(stream: &mut DirStream) -> Result<Option<NewlibDirent>, c_int> {
    loop {
        if stream.buffer_offset >= stream.buffer_len && !refill_dir_stream(stream)? {
            return Ok(None);
        }

        let offset = stream.buffer_offset;
        let record = &stream.buffer[offset..stream.buffer_len];
        let (header, name, consumed) =
            filesystem_protocol::decode_dir_entry(record).map_err(|_| EIO)?;
        let dtype = match header.kind {
            filesystem_protocol::NODE_TYPE_REGULAR => 8,
            filesystem_protocol::NODE_TYPE_DIRECTORY => 4,
            filesystem_protocol::NODE_TYPE_SYMLINK => 10,
            _ => 0,
        };
        let (inode, name) = (header.node_id, name);
        let copy_len = core::cmp::min(name.len(), DIRENT_NAME_MAX - 1);

        let mut out = NewlibDirent::empty();
        out.d_ino = inode;
        out.d_type = dtype;
        for index in 0..copy_len {
            out.d_name[index] = name[index] as c_char;
        }

        let _native = defer_native_delivery();
        stream.buffer_offset += consumed;
        stream.next_position = header.next_position;
        return Ok(Some(out));
    }
}

fn startup_failure(stage: &[u8], error: c_int) -> ! {
    let _ = syscall::raw_syscall2(
        syscall::SyscallNumber::DebugWrite,
        stage.as_ptr() as u64,
        stage.len() as u64,
    );
    let mut digits = [0u8; 12];
    let mut position = digits.len() - 1;
    digits[position] = b'\n';
    let mut value = error.unsigned_abs();
    loop {
        position -= 1;
        digits[position] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let _ = syscall::raw_syscall2(
        syscall::SyscallNumber::DebugWrite,
        digits[position..].as_ptr() as u64,
        (digits.len() - position) as u64,
    );
    process_exit(127)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start_c(initial_sp: *const usize) -> ! {
    let stack = unsafe { parse_stack(initial_sp) };
    if let Err(error) = resource_policy::adopt_initial(stack.resource_policy) {
        startup_failure(b"newlib: initial resource policy failed: ", error);
    }
    unsafe { initialize_runtime(stack) };
    match has_posix_environment() {
        Ok(false) => {}
        Ok(true) => match posix_client().and_then(|client| client.signal_image_started()) {
            Ok(ignored) => {
                let mut actions = SIGNAL_ACTIONS.lock();
                for (index, action) in actions.iter_mut().enumerate() {
                    if ignored & (1u64 << index) != 0 {
                        action.handler = 1;
                    }
                }
            }
            Err(error) => {
                startup_failure(
                    b"newlib: POSIX startup failed: ",
                    map_posix_client_error(error),
                );
            }
        },
        Err(_) => process_exit(127),
    }
    let (_, initial_thread) = register_initial_thread().unwrap_or_else(|| process_exit(127));
    let prepared_stack = (stack.upcall_stack != 0).then_some(stack.upcall_stack);
    if let Err(error) = setup_signal_delivery(initial_thread, prepared_stack) {
        startup_failure(b"newlib: signal startup failed: ", error);
    }
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
    // Pipe and stream-socket operations own only their borrow-book pin.
    // Datagram, terminal and file paths retain the ordinary fork blocker.
    let result = unsafe {
        io_resources::with_fork_opaque(
            || with_fd_entry(fd),
            |entry| matches!(
                entry.handle.kind,
                FdKind::ObjectStreamWrite | FdKind::ObjectSocket
            ),
            |entry| syscall_write(**entry, buffer, length),
        )
    };
    record_stdio_io(&result);
    result_with_errno(result, -1)
}

// This newlib configuration omits libc/syscalls/sys*.c connectors, and some
// reentrant wrappers still resolve through the plain POSIX spellings.
#[unsafe(no_mangle)]
pub extern "C" fn write(fd: c_int, buffer: *const c_void, length: usize) -> isize {
    pthread_testcancel();
    finish_io_cancellation(_write(fd, buffer, length))
}

fn finish_io_cancellation(result: isize) -> isize {
    // Report committed progress rather than hiding a transferred prefix. A
    // pending request remains pending for the next cancellation point.
    // _read/_write also back newlib stdio under FILE locks: only the public
    // API exits a thread, after internal callers and their cleanup have returned.
    if result <= 0 {
        pthread_testcancel();
    }
    result
}

fn vector_errno(error: mochios_posix_client::io_vector::VectorError) -> c_int {
    match error {
        mochios_posix_client::io_vector::VectorError::NullBuffer => EFAULT,
        mochios_posix_client::io_vector::VectorError::InvalidCount
        | mochios_posix_client::io_vector::VectorError::InvalidLength => EINVAL,
    }
}

fn capture_vector_metadata(
    source: *const IoVecMut,
    count: c_int,
    metadata: &mut VectorMetadata,
) -> Result<usize, c_int> {
    if count < 0 || count as usize > mochios_posix_client::io_vector::IOV_MAX {
        return Err(EINVAL);
    }
    // Own each record before a returning callback can change/unmap its array.
    for index in 0..count as usize {
        let (base, length) = vector_memory::read(source, index)?;
        metadata.set(index, base.cast(), length);
    }
    mochios_posix_client::io_vector::validate(count, |index| {
        let (base, length) = metadata.get(index);
        (base.is_null(), length)
    })
    .map_err(vector_errno)
}

struct VectorBuffer {
    pointer: *mut u8,
    length: usize,
}

impl VectorBuffer {
    fn new(total: usize) -> Result<Self, c_int> {
        let length = total.min(mochios_posix_client::io_vector::MAX_TRANSFER_BYTES);
        // newlib owns allocation; the freestanding runtime has no Rust allocator.
        let pointer = if length == 0 {
            core::ptr::NonNull::<u8>::dangling().as_ptr()
        } else {
            let pointer = unsafe { malloc(length) }.cast::<u8>();
            if pointer.is_null() {
                return Err(ENOMEM);
            }
            // Initialize storage before forming a safe Rust slice.
            unsafe { ptr::write_bytes(pointer, 0, length) };
            pointer
        };
        Ok(Self { pointer, length })
    }

    fn bytes(&mut self) -> &mut [u8] {
        // Safety: owned, initialized allocation (or aligned dangling pointer for zero).
        unsafe { core::slice::from_raw_parts_mut(self.pointer, self.length) }
    }
}

impl Drop for VectorBuffer {
    fn drop(&mut self) {
        if self.length != 0 {
            unsafe { free(self.pointer.cast()) };
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn writev(fd: c_int, iov: *const IoVec, iovcnt: c_int) -> isize {
    pthread_testcancel();
    if iovcnt < 0 || iovcnt as usize > mochios_posix_client::io_vector::IOV_MAX {
        set_errno(EINVAL);
        return -1;
    }
    if iovcnt != 0 && iov.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    // Only fully prepared FD pins and private buffers survive this snapshot.
    let result = unsafe {
        io_resources::with_initialized_fork_opaque(
            || {
                Ok((
                    with_fd_entry(fd)?,
                    VectorMetadata::new(iovcnt as usize)?,
                    None::<VectorBuffer>,
                ))
            },
            |(_, metadata, buffer)| {
                let total = capture_vector_metadata(iov.cast(), iovcnt, metadata)?;
                *buffer = Some(VectorBuffer::new(total)?);
                Ok(())
            },
            |(entry, _, _)| matches!(
                entry.handle.kind,
                FdKind::ObjectStreamWrite | FdKind::ObjectSocket
            ),
            |(entry, metadata, buffer)| {
                mochios_posix_client::io_vector::write(
                    iovcnt as usize,
                    buffer.as_mut().unwrap().bytes(),
                    |index| metadata.get(index).1,
                    |index, bytes| {
                        let (base, _) = metadata.get(index);
                        user_copy::read(base.cast(), bytes)
                    },
                    |bytes| {
                        syscall_write(**entry, bytes.as_ptr().cast(), bytes.len())
                            .and_then(|count| usize::try_from(count).map_err(|_| EIO))
                    },
                )
                .map(|count| count as isize)
                .map_err(|error| match error {
                    mochios_posix_client::io_vector::TransferError::InvalidResult => EIO,
                    mochios_posix_client::io_vector::TransferError::Io(errno) => errno,
                })
            },
        )
    };
    finish_io_cancellation(result_with_errno(result, -1))
}

#[unsafe(no_mangle)]
pub extern "C" fn _read(fd: c_int, buffer: *mut c_void, length: usize) -> isize {
    if length != 0 && buffer.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    #[cfg(feature = "trace-io")]
    let trace = io_trace::read(fd, length);
    // Stream sockets, like pipes, use no temporary native references.
    let result = unsafe {
        io_resources::with_fork_opaque(
            || with_fd_entry(fd),
            |entry| matches!(
                entry.handle.kind,
                FdKind::ObjectStreamRead | FdKind::ObjectSocket
            ),
            |entry| syscall_read(**entry, buffer, length),
        )
    };
    record_stdio_io(&result);
    #[cfg(feature = "trace-io")]
    if let Some(trace) = trace {
        trace.finish(result);
    }
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn read(fd: c_int, buffer: *mut c_void, length: usize) -> isize {
    pthread_testcancel();
    finish_io_cancellation(_read(fd, buffer, length))
}

fn positioned_file_io(
    fd: c_int,
    buffer: *mut c_void,
    length: usize,
    offset: i64,
    write: bool,
) -> Result<isize, c_int> {
    io_resources::with(
        || with_fd_entry(fd),
        |entry| positioned_entry_io(**entry, buffer, length, offset, write),
    )
}

fn positioned_entry_io(
    entry: FdEntry,
    buffer: *mut c_void,
    length: usize,
    offset: i64,
    write: bool,
) -> Result<isize, c_int> {
    let offset = mochios_posix_client::fd::positioned_offset(offset, length).ok_or(EINVAL)?;
    if length != 0 && buffer.is_null() {
        return Err(EFAULT);
    }
    match entry.handle.kind {
        FdKind::ObjectFile | FdKind::ObjectSpecial | FdKind::ObjectSharedMemory => {}
        FdKind::ObjectDirectory => return Err(EISDIR),
        _ => return Err(ESPIPE),
    }
    let allowed = if write {
        mochios_posix_client::fd::access_allows_write(entry.handle.open_flags as u32)
    } else {
        mochios_posix_client::fd::access_allows_read(entry.handle.open_flags as u32)
    };
    if !allowed {
        return Err(EBADF);
    }
    let length = if write
        && length != 0
        && matches!(
            entry.handle.kind,
            FdKind::ObjectFile | FdKind::ObjectSharedMemory
        ) {
        let limit = resource_policy::read(posix_protocol::RLIMIT_FSIZE)?;
        match mochios_posix_client::file_size_limit::positioned_length(offset, length, limit.soft) {
            Some(length) => length,
            None => {
                generate_thread_signal(posix_protocol::SIGNAL_XFSZ)?;
                return Err(EFBIG);
            }
        }
    } else {
        length
    };
    let operation = if write {
        syscall::SyscallNumber::HandleWriteAt
    } else {
        syscall::SyscallNumber::HandleReadAt
    };
    let count = syscall_errno(syscall::raw_syscall4(
        operation,
        entry.handle.lower_handle,
        buffer as u64,
        length as u64,
        offset,
    ))?;
    if count > length as u64 {
        return Err(EIO);
    }
    Ok(count as isize)
}

#[unsafe(no_mangle)]
pub extern "C" fn pread(fd: c_int, buffer: *mut c_void, length: usize, offset: i64) -> isize {
    pthread_testcancel();
    finish_io_cancellation(result_with_errno(
        positioned_file_io(fd, buffer, length, offset, false),
        -1,
    ))
}

#[unsafe(no_mangle)]
pub extern "C" fn pwrite(fd: c_int, buffer: *const c_void, length: usize, offset: i64) -> isize {
    pthread_testcancel();
    finish_io_cancellation(result_with_errno(
        positioned_file_io(fd, buffer.cast_mut(), length, offset, true),
        -1,
    ))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn readv(fd: c_int, iov: *const IoVecMut, iovcnt: c_int) -> isize {
    pthread_testcancel();
    if iovcnt < 0 || iovcnt as usize > mochios_posix_client::io_vector::IOV_MAX {
        set_errno(EINVAL);
        return -1;
    }
    if iovcnt != 0 && iov.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    // Only fully prepared FD pins and private buffers survive this snapshot.
    let result = unsafe {
        io_resources::with_initialized_fork_opaque(
            || {
                Ok((
                    with_fd_entry(fd)?,
                    VectorMetadata::new(iovcnt as usize)?,
                    None::<VectorBuffer>,
                ))
            },
            |(_, metadata, buffer)| {
                let total = capture_vector_metadata(iov, iovcnt, metadata)?;
                *buffer = Some(VectorBuffer::new(total)?);
                Ok(())
            },
            |(entry, _, _)| matches!(
                entry.handle.kind,
                FdKind::ObjectStreamRead | FdKind::ObjectSocket
            ),
            |(entry, metadata, buffer)| {
                mochios_posix_client::io_vector::read(
                    iovcnt as usize,
                    buffer.as_mut().unwrap().bytes(),
                    |index| metadata.get(index).1,
                    |index, bytes| {
                        let (base, _) = metadata.get(index);
                        user_copy::write(base.cast(), bytes)
                    },
                    |bytes| {
                        syscall_read(**entry, bytes.as_mut_ptr().cast(), bytes.len())
                            .and_then(|count| usize::try_from(count).map_err(|_| EIO))
                    },
                )
                .map(|count| count as isize)
                .map_err(|error| match error {
                    mochios_posix_client::io_vector::TransferError::InvalidResult => EIO,
                    mochios_posix_client::io_vector::TransferError::Io(errno) => errno,
                })
            },
        )
    };
    finish_io_cancellation(result_with_errno(result, -1))
}

#[unsafe(no_mangle)]
pub extern "C" fn _open(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    #[cfg(feature = "trace-io")]
    let trace = io_trace::open(flags);
    let result = match file_mutation::open(path, flags, mode) {
        Err(errno) if errno == EACCES || errno == EPERM => {
            retry_open_with_prompt(path, flags, mode)
        }
        result => result,
    };
    if matches!(result, Err(EINTR)) {
        if let Some((_, control)) = current_thread_control() {
            if io_cancellation_requested(control) {
                control.stdio_scope.note_interruption();
            }
        }
    }
    #[cfg(feature = "trace-io")]
    trace.finish(result);
    // Internal newlib callers must finish FILE/list cleanup before exiting.
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn open(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
    pthread_testcancel();
    let result = _open(path, flags, mode);
    if result < 0 {
        // The internal operation has retired its Handle and FD reservation.
        pthread_testcancel();
    }
    // A successfully published descriptor belongs to the caller. Do not hide
    // it if completion won the race; retain cancellation for the next point.
    result
}

#[unsafe(no_mangle)]
pub extern "C" fn openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: c_int) -> c_int {
    pthread_testcancel();
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    // A directory Handle, never an expanded pathname or ambient grant, is
    // captured and retained through queued admission and FD publication.
    let result = result_with_errno(file_mutation::open_at(dirfd, path, flags, mode), -1);
    if result < 0 {
        pthread_testcancel();
    }
    result
}

#[unsafe(no_mangle)]
pub extern "C" fn _close(fd: c_int) -> c_int {
    let result = (|| {
        let mut state = state();
        close_fd_entry(&mut state.fds, fd)?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn close(fd: c_int) -> c_int {
    pthread_testcancel();
    let result = _close(fd);
    if result < 0 {
        // _close has released STATE and any native-reference bookkeeping.
        pthread_testcancel();
    }
    // Do not hide a completed close: the descriptor number may already have
    // been reused by another thread. Retain concurrent cancellation instead.
    result
}

#[unsafe(no_mangle)]
pub extern "C" fn ptsname_r(fd: c_int, output: *mut c_char, capacity: usize) -> c_int {
    match terminal_name::get(fd, output, capacity) {
        Ok(result) => result,
        Err(error) => {
            set_errno(error);
            error
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ptsname(fd: c_int) -> *mut c_char {
    let result = register_current_thread()
        .ok_or(EAGAIN)
        .and_then(|(_, control)| {
            // SAFETY: Only this thread accesses its registered control's buffer.
            // THREADS has static storage, and its slot cannot be reused while the
            // native thread remains live. No Rust reference to bytes is returned.
            unsafe { terminal_name::owned(fd, &control.ptsname_buffer) }
        });
    match result {
        Ok(output) => output,
        Err(error) => {
            set_errno(error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn openpty(
    master: *mut c_int,
    slave: *mut c_int,
    name: *mut c_char,
    termios: *const NewlibTermios,
    window_size: *const c_void,
) -> c_int {
    if master.is_null() || slave.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(
        pty_creation::create(master, slave, name, termios, window_size.cast()),
        -1,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn _pipe2(fds: *mut c_int, flags: c_int) -> c_int {
    if fds.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
        set_errno(EINVAL);
        return -1;
    }
    result_with_errno(pipe::create(fds, flags), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn pipe2(fds: *mut c_int, flags: c_int) -> c_int {
    _pipe2(fds, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn _pipe(fds: *mut c_int) -> c_int {
    _pipe2(fds, 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn pipe(fds: *mut c_int) -> c_int {
    _pipe(fds)
}

#[unsafe(no_mangle)]
pub extern "C" fn fork() -> c_int {
    result_with_errno(atfork::run(clone_registered_process), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn dup(fd: c_int) -> c_int {
    let result = (|| {
        with_fd_entry(fd)?;
        let limit = process_fd_limit()?;
        duplicate_fd_from(&mut state().fds, fd, None, false, limit)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn dup2(old_fd: c_int, new_fd: c_int) -> c_int {
    result_with_errno(duplicate_live_fd(old_fd, new_fd), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn fcntl(fd: c_int, cmd: c_int, arg: c_int) -> c_int {
    let result = (|| {
        if fd < 0 || fd as usize >= MAX_FDS {
            return Err(EBADF);
        }
        if matches!(cmd, F_GETFL | F_SETFL) {
            return fd_options::status(fd, cmd, arg);
        }
        // Read policy before locking the FD table. Fork uses
        // allocator -> POLICY -> STATE; policy discovery itself never mallocs.
        let limit = if matches!(cmd, F_DUPFD | F_DUPFD_CLOEXEC) {
            with_fd_entry(fd)?;
            process_fd_limit()?
        } else {
            MAX_FDS as c_int
        };
        let mut state = state();
        let entry = state.fds.get(fd).ok_or(EBADF)?;
        match cmd {
            F_DUPFD | F_DUPFD_CLOEXEC => {
                duplicate_fd_from(&mut state.fds, fd, Some(arg), cmd == F_DUPFD_CLOEXEC, limit)
            }
            F_GETFD => Ok(entry.descriptor_flags as c_int),
            F_SETFD => {
                state
                    .fds
                    .set_descriptor_flags(fd, (arg & FD_CLOEXEC) as u32)
                    .map_err(|_| EBADF)?;
                Ok(0)
            }
            _ => Err(EINVAL),
        }
    })();
    result_with_errno(result, -1)
}

fn native_monotonic_nanoseconds() -> Result<u64, syscall::SysError> {
    let mut instant = mnu_abi::ClockInstant::default();
    syscall::raw_syscall2(
        syscall::SyscallNumber::ClockRead,
        mnu_abi::ClockId::Monotonic as u64,
        (&mut instant as *mut mnu_abi::ClockInstant) as u64,
    )
    .into_result()?;
    if instant.nanoseconds >= 1_000_000_000 || instant.reserved != 0 {
        return Err(syscall::NativeError::BackingFailure.into_raw().into());
    }
    instant
        .seconds
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(u64::from(instant.nanoseconds)))
        .ok_or_else(|| syscall::NativeError::LimitExceeded.into_raw().into())
}

fn monotonic_nanoseconds() -> Result<u64, c_int> {
    native_monotonic_nanoseconds().map_err(|error| map_kernel_errno(error.raw()))
}

fn deadline_after_nanoseconds(duration: u64) -> Result<u64, c_int> {
    if duration == 0 {
        return Ok(syscall::HANDLE_WAIT_POLL);
    }
    monotonic_nanoseconds()?
        .checked_add(duration)
        .ok_or(EOVERFLOW)
}

/// Private runtime bridge used by the mochiOS Rust standard library. The
/// result is the native `AddressWaitResult`, or a negative native error.
#[unsafe(no_mangle)]
pub extern "C" fn __mochios_wait_on_address_u32(
    address: *const core::sync::atomic::AtomicU32,
    expected: u32,
    timeout_nanoseconds: u64,
) -> u64 {
    if address.is_null() {
        return syscall::NativeError::InvalidAddress.into_raw();
    }
    let deadline = if timeout_nanoseconds == u64::MAX {
        syscall::ADDRESS_WAIT_INFINITE
    } else {
        match native_monotonic_nanoseconds() {
            Ok(now) => match now.checked_add(timeout_nanoseconds) {
                Some(deadline) if deadline != syscall::ADDRESS_WAIT_INFINITE => deadline,
                _ => return syscall::NativeError::LimitExceeded.into_raw(),
            },
            Err(error) => return error.raw() as u64,
        }
    };
    match mochios_posix_client::synchronization::wait_u32_address(address as u64, expected, deadline)
    {
        Ok(mochios_posix_client::synchronization::WaitStatus::Awoken) => {
            syscall::AddressWaitResult::Awoken as u64
        }
        Ok(mochios_posix_client::synchronization::WaitStatus::ValueChanged) => {
            syscall::AddressWaitResult::ValueChanged as u64
        }
        Ok(mochios_posix_client::synchronization::WaitStatus::DeadlineReached) => {
            syscall::AddressWaitResult::DeadlineReached as u64
        }
        Err(error) => error.raw() as u64,
    }
}

/// Private runtime bridge used by the mochiOS Rust standard library. Returns
/// the number of waiters woken, or a negative native error.
#[unsafe(no_mangle)]
pub extern "C" fn __mochios_wake_address_u32(
    address: *const core::sync::atomic::AtomicU32,
    maximum_count: usize,
) -> u64 {
    if address.is_null() {
        return syscall::NativeError::InvalidAddress.into_raw();
    }
    match mochios_posix_client::synchronization::wake_u32_address(address as u64, maximum_count) {
        Ok(count) => count as u64,
        Err(error) => error.raw() as u64,
    }
}

fn wait_for_multiplex(
    items: &mut [syscall::HandleWaitItem],
    deadline: u64,
    control: &ThreadControl,
    caught: u64,
) -> Result<(), c_int> {
    wait_for_multiplex_while(items, deadline, control, caught, || true)
}

fn wait_for_multiplex_while(
    items: &mut [syscall::HandleWaitItem],
    deadline: u64,
    control: &ThreadControl,
    caught: u64,
    valid: impl Fn() -> bool,
) -> Result<(), c_int> {
    mochios_posix_client::multiplex::wait_cancellable(
        caught,
        || control.caught_signal_generation.load(Ordering::Acquire),
        || {
            !valid() || (control.cancel_state.load(Ordering::Acquire) == PTHREAD_CANCEL_ENABLE
                && control.cancel_pending.load(Ordering::Acquire) != 0)
        },
        || control.multiplex_generation.load(Ordering::Acquire),
        |notification| {
            let guard = syscall::HandleWaitGuard {
                address: (&control.multiplex_generation as *const AtomicU64) as u64,
                expected: notification,
            };
            if !valid() {
                return Ok(false);
            }
            let result = syscall_errno(syscall::raw_syscall4(
                syscall::SyscallNumber::HandleWaitManyGuarded,
                items.as_mut_ptr() as u64,
                items.len() as u64,
                deadline,
                (&guard as *const syscall::HandleWaitGuard) as u64,
            ));
            // A returning handler may fork even while the native call is
            // failing. That result and its observed bits belong to the old
            // reference lifetime; let the cancellation predicate retire it.
            if !valid() {
                return Ok(false);
            }
            match result {
                Ok(_) => Ok(true),
                Err(EAGAIN) => Ok(false),
                Err(error) => Err(error),
            }
        },
        || {
            if deadline == syscall::HANDLE_WAIT_POLL {
                Ok(true)
            } else if deadline == syscall::HANDLE_WAIT_INFINITE {
                Ok(false)
            } else {
                monotonic_nanoseconds().map(|now| now >= deadline)
            }
        },
    )
    .map_err(|error| match error {
        mochios_posix_client::multiplex::WaitError::Interrupted => EINTR,
        // Masked waits restore their mask before the public API cancels.
        mochios_posix_client::multiplex::WaitError::Cancelled => EINTR,
        mochios_posix_client::multiplex::WaitError::Io(error) => error,
    })
}

fn select_deadline(timeout: *const Timeval) -> Result<u64, c_int> {
    if timeout.is_null() {
        return Ok(syscall::HANDLE_WAIT_INFINITE);
    }
    let timeout = multiplex_memory::read_timeval(timeout)?;
    if timeout.tv_sec < 0 || !(0..1_000_000).contains(&timeout.tv_usec) {
        return Err(EINVAL);
    }
    let duration = u64::try_from(timeout.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(timeout.tv_usec)
                .ok()
                .and_then(|microseconds| seconds.checked_add(microseconds * 1_000))
        })
        .ok_or(EOVERFLOW)?;
    deadline_after_nanoseconds(duration)
}

#[unsafe(no_mangle)]
pub extern "C" fn select(
    nfds: c_int,
    readfds: *mut FdSet,
    writefds: *mut FdSet,
    exceptfds: *mut FdSet,
    timeout: *mut Timeval,
) -> c_int {
    pthread_testcancel();
    let result = (|| {
        if nfds < 0 || nfds as usize > MAX_FDS {
            return Err(EINVAL);
        }
        let (_, control) = register_current_thread().ok_or(EAGAIN)?;
        let caught = control.caught_signal_generation.load(Ordering::Acquire);
        let deadline = select_deadline(timeout)?;
        select_with_deadline(nfds, readfds, writefds, exceptfds, deadline, control, caught)
    })();
    pthread_testcancel();
    result_with_errno(result, -1)
}

fn select_with_deadline(
    nfds: c_int,
    readfds: *mut FdSet,
    writefds: *mut FdSet,
    exceptfds: *mut FdSet,
    requested_deadline: u64,
    control: &ThreadControl,
    caught: u64,
) -> Result<c_int, c_int> {
    // Snapshot all FD pins before readiness queries. The remaining path
    // borrows these Handles and private arrays without creating references.
    unsafe {
        io_resources::with_initialized_fork_opaque(
            || Ok(([const { None }; MAX_FDS], [0u64; 3])),
            |(leases, masks)| {
                if nfds < 0 || nfds as usize > MAX_FDS {
                    return Err(EINVAL);
                }
                let requested_read = if readfds.is_null() {
                    0
                } else {
                    multiplex_memory::read_mask(readfds.cast())?
                };
                let requested_write = if writefds.is_null() {
                    0
                } else {
                    multiplex_memory::read_mask(writefds.cast())?
                };
                let requested_except = if exceptfds.is_null() {
                    0
                } else {
                    multiplex_memory::read_mask(exceptfds.cast())?
                };
                let valid_mask = if nfds == 64 {
                    u64::MAX
                } else if nfds == 0 {
                    0
                } else {
                    (1u64 << nfds) - 1
                };
                let requested_read = requested_read & valid_mask;
                let requested_write = requested_write & valid_mask;
                let requested_except = requested_except & valid_mask;
                let requested = requested_read | requested_write | requested_except;

                *masks = [requested_read, requested_write, requested_except];
                for fd in 0..nfds as usize {
                    if requested & (1u64 << fd) != 0 {
                        leases[fd] = Some(with_fd_entry(fd as c_int)?);
                    }
                }
                Ok(())
            },
            |_| true,
            |(leases, masks)| {
                let [requested_read, requested_write, requested_except] = *masks;
                let requested = requested_read | requested_write | requested_except;

                let mut ready_read = 0u64;
                let mut ready_write = 0u64;
                let ready_except = 0u64;
                let mut items = [syscall::HandleWaitItem::default(); MAX_FDS];
                let mut item_fds = [0usize; MAX_FDS];
                let mut item_count = 0usize;
                for fd in 0..nfds as usize {
                    let mask = 1u64 << fd;
                    if requested & mask == 0 {
                        continue;
                    }
                    let entry = leases[fd].as_ref().unwrap();
                    match entry.handle.kind {
                        FdKind::ObjectStreamRead if requested_read & mask != 0 => {
                            items[item_count] = syscall::HandleWaitItem {
                                handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                                minimum_write_bytes: 0,
                                interests: syscall::HANDLE_SIGNAL_READABLE
                                    | syscall::HANDLE_SIGNAL_PEER_CLOSED,
                                observed: 0,
                            };
                            item_fds[item_count] = fd;
                            item_count += 1;
                            if requested_write & mask != 0 {
                                ready_write |= requested_write & mask;
                            }
                        }
                        FdKind::ObjectStreamWrite if requested_write & mask != 0 => {
                            items[item_count] = syscall::HandleWaitItem {
                                handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                                minimum_write_bytes: 0,
                                interests: syscall::HANDLE_SIGNAL_WRITABLE
                                    | syscall::HANDLE_SIGNAL_PEER_CLOSED,
                                observed: 0,
                            };
                            item_fds[item_count] = fd;
                            item_count += 1;
                            if requested_read & mask != 0 {
                                ready_read |= requested_read & mask;
                            }
                        }
                        FdKind::ObjectPty
                        | FdKind::ObjectTerminalFile
                        | FdKind::ObjectSocket
                        | FdKind::ObjectDatagram => {
                            let mut interests = if entry.handle.kind.is_socket() {
                                0
                            } else {
                                syscall::HANDLE_SIGNAL_PEER_CLOSED
                            };
                            if requested_read & mask != 0 {
                                interests |= syscall::HANDLE_SIGNAL_READABLE;
                            }
                            if requested_write & mask != 0 {
                                interests |= syscall::HANDLE_SIGNAL_WRITABLE;
                            }
                            items[item_count] = syscall::HandleWaitItem {
                                handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                                minimum_write_bytes: 0,
                                interests,
                                observed: 0,
                            };
                            item_fds[item_count] = fd;
                            item_count += 1;
                        }
                        FdKind::ObjectStreamRead | FdKind::ObjectStreamWrite => {
                            ready_read |= requested_read & mask;
                            ready_write |= requested_write & mask;
                        }
                        _ => {
                            ready_read |= requested_read & mask;
                            ready_write |= requested_write & mask;
                        }
                    }
                }

                let deadline = if ready_read | ready_write | ready_except != 0 {
                    syscall::HANDLE_WAIT_POLL
                } else {
                    requested_deadline
                };
                wait_for_multiplex(&mut items[..item_count], deadline, control, caught)?;
                for index in 0..item_count {
                    let fd = item_fds[index];
                    let mask = 1u64 << fd;
                    let observed = items[index].observed;
                    if observed & (syscall::HANDLE_SIGNAL_READABLE | syscall::HANDLE_SIGNAL_PEER_CLOSED)
                        != 0
                    {
                        ready_read |= requested_read & mask;
                    }
                    if observed & (syscall::HANDLE_SIGNAL_WRITABLE | syscall::HANDLE_SIGNAL_PEER_CLOSED)
                        != 0
                    {
                        ready_write |= requested_write & mask;
                    }
                }
                if !readfds.is_null() {
                    user_copy::write(readfds.cast(), &ready_read.to_ne_bytes())?;
                }
                if !writefds.is_null() {
                    user_copy::write(writefds.cast(), &ready_write.to_ne_bytes())?;
                }
                if !exceptfds.is_null() {
                    user_copy::write(exceptfds.cast(), &ready_except.to_ne_bytes())?;
                }
                Ok(mochios_posix_client::multiplex::select_ready_count(
                    ready_read,
                    ready_write,
                    ready_except,
                ) as c_int)
            },
        )
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn poll(fds: *mut PollFd, nfds: u32, timeout_ms: c_int) -> c_int {
    pthread_testcancel();
    let result = (|| {
        if nfds as usize > MAX_FDS {
            return Err(EINVAL);
        }
        if nfds != 0 && fds.is_null() {
            return Err(EFAULT);
        }
        let (_, control) = register_current_thread().ok_or(EAGAIN)?;
        let caught = control.caught_signal_generation.load(Ordering::Acquire);
        let deadline = match mochios_posix_client::multiplex::poll_timeout_nanoseconds(timeout_ms) {
            None => syscall::HANDLE_WAIT_INFINITE,
            Some(duration) => deadline_after_nanoseconds(duration)?,
        };
        poll_with_deadline(fds, nfds, deadline, control, caught)
    })();
    pthread_testcancel();
    result_with_errno(result, -1)
}

fn poll_with_deadline(
    fds: *mut PollFd,
    nfds: u32,
    deadline: u64,
    control: &ThreadControl,
    caught: u64,
) -> Result<c_int, c_int> {
    let count = usize::try_from(nfds).map_err(|_| EINVAL)?;
    // Snapshot all FD pins before readiness queries. The remaining path
    // borrows these Handles and private arrays without creating references.
    unsafe {
        io_resources::with_initialized_fork_opaque(
            || Ok(([const { None }; MAX_FDS], [PollFd::default(); MAX_FDS])),
            |(leases, pollfds)| {
                if count > MAX_FDS {
                    return Err(EINVAL);
                }
                if count != 0 && fds.is_null() {
                    return Err(EFAULT);
                }
                // Capture the entire caller list before any provider may invoke C.
                multiplex_memory::read_pollfds(fds, &mut pollfds[..count])?;
                for index in 0..count {
                    if pollfds[index].fd >= 0 {
                        leases[index] = with_fd_entry(pollfds[index].fd).ok();
                    }
                }
                Ok(())
            },
            |_| true,
            |(leases, pollfds)| {
                const READ_EVENTS: i16 = mochios_posix_client::multiplex::NORMAL_READ_EVENTS;
                const WRITE_EVENTS: i16 = mochios_posix_client::multiplex::NORMAL_WRITE_EVENTS;
                let mut items = [syscall::HandleWaitItem::default(); MAX_FDS];
                let mut item_pollfds = [0usize; MAX_FDS];
                let mut item_kinds = [FdKind::Unused; MAX_FDS];
                let mut item_count = 0usize;
                let mut immediately_ready = false;
                for index in 0..count {
                    pollfds[index].revents = 0;
                    let fd = pollfds[index].fd;
                    if fd < 0 {
                        continue;
                    }
                    let Some(entry) = leases[index].as_ref() else {
                        pollfds[index].revents = POLLNVAL;
                        immediately_ready = true;
                        continue;
                    };
                    match entry.handle.kind {
                        FdKind::ObjectSocket | FdKind::ObjectDatagram => {
                            pollfds[index].revents =
                                socket::poll_events(**entry, pollfds[index].events)?;
                            immediately_ready |= pollfds[index].revents != 0;
                            let mut interests = syscall::HANDLE_SIGNAL_PEER_CLOSED;
                            if pollfds[index].events & READ_EVENTS != 0 {
                                interests |= syscall::HANDLE_SIGNAL_READABLE;
                            }
                            if pollfds[index].events & WRITE_EVENTS != 0 {
                                interests |= syscall::HANDLE_SIGNAL_WRITABLE;
                            }
                            items[item_count] = syscall::HandleWaitItem {
                                handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                                minimum_write_bytes: 0,
                                interests,
                                observed: 0,
                            };
                            item_pollfds[item_count] = index;
                            item_kinds[item_count] = entry.handle.kind;
                            item_count += 1;
                        }
                        FdKind::ObjectStreamRead
                        | FdKind::ObjectStreamWrite
                        | FdKind::ObjectPty
                        | FdKind::ObjectTerminalFile => {
                            let mut interests = syscall::HANDLE_SIGNAL_PEER_CLOSED;
                            if matches!(
                                entry.handle.kind,
                                FdKind::ObjectStreamRead | FdKind::ObjectPty | FdKind::ObjectTerminalFile
                            ) && pollfds[index].events & READ_EVENTS != 0
                            {
                                interests |= syscall::HANDLE_SIGNAL_READABLE;
                            }
                            if matches!(
                                entry.handle.kind,
                                FdKind::ObjectStreamWrite | FdKind::ObjectPty | FdKind::ObjectTerminalFile
                            ) && pollfds[index].events & WRITE_EVENTS != 0
                            {
                                interests |= syscall::HANDLE_SIGNAL_WRITABLE;
                            }
                            items[item_count] = syscall::HandleWaitItem {
                                handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                                minimum_write_bytes: 0,
                                interests,
                                observed: 0,
                            };
                            item_pollfds[item_count] = index;
                            item_kinds[item_count] = entry.handle.kind;
                            item_count += 1;
                        }
                        _ => {
                            pollfds[index].revents =
                                mochios_posix_client::multiplex::immediate_file_events(
                                    pollfds[index].events,
                                );
                            immediately_ready |= pollfds[index].revents != 0;
                        }
                    }
                }

                let wait_deadline = if immediately_ready {
                    syscall::HANDLE_WAIT_POLL
                } else {
                    deadline
                };
                wait_for_multiplex(&mut items[..item_count], wait_deadline, control, caught)?;
                for item_index in 0..item_count {
                    let poll_index = item_pollfds[item_index];
                    if item_kinds[item_index].is_socket() {
                        pollfds[poll_index].revents = socket::poll_events(
                            **leases[poll_index].as_ref().unwrap(),
                            pollfds[poll_index].events,
                        )?;
                        continue;
                    }
                    let observed = items[item_index].observed;
                    if observed & syscall::HANDLE_SIGNAL_READABLE != 0 {
                        pollfds[poll_index].revents |= pollfds[poll_index].events & READ_EVENTS;
                    }
                    if observed & syscall::HANDLE_SIGNAL_WRITABLE != 0 {
                        pollfds[poll_index].revents |= pollfds[poll_index].events & WRITE_EVENTS;
                    }
                    if observed & syscall::HANDLE_SIGNAL_PEER_CLOSED != 0 {
                        match item_kinds[item_index] {
                            FdKind::ObjectStreamRead => {
                                pollfds[poll_index].revents |= POLLHUP;
                                pollfds[poll_index].revents |= pollfds[poll_index].events & READ_EVENTS;
                            }
                            FdKind::ObjectStreamWrite => pollfds[poll_index].revents |= POLLERR,
                            FdKind::ObjectPty | FdKind::ObjectTerminalFile => {
                                pollfds[poll_index].revents |= POLLHUP;
                                pollfds[poll_index].revents |= pollfds[poll_index].events & READ_EVENTS;
                                if pollfds[poll_index].events & WRITE_EVENTS != 0 {
                                    pollfds[poll_index].revents |= POLLERR;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                let mut ready = 0usize;
                for index in 0..count {
                    if pollfds[index].revents != 0 {
                        ready += 1;
                    }
                }
                multiplex_memory::write_pollfds(fds, &pollfds[..count])?;
                c_int::try_from(ready).map_err(|_| EOVERFLOW)
            },
        )
    }
}

fn timespec_deadline(timeout: *const NewlibTimespec) -> Result<u64, c_int> {
    if timeout.is_null() {
        return Ok(syscall::HANDLE_WAIT_INFINITE);
    }
    let value = multiplex_memory::read_timespec(timeout)?;
    let duration =
        mochios_posix_client::multiplex::timespec_timeout_nanoseconds(value.tv_sec, value.tv_nsec)
            .ok_or(EINVAL)?;
    deadline_after_nanoseconds(duration)
}

fn masked_multiplex(
    mask: *const u64,
    operation: impl FnOnce(&ThreadControl, u64) -> Result<c_int, c_int>,
) -> Result<c_int, c_int> {
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let has_signals = has_posix_environment()?;
    // Capture before unblocking: an upcall may execute during the mask RPC.
    let caught = control.caught_signal_generation.load(Ordering::Acquire);
    let mask = if mask.is_null() {
        None
    } else {
        Some(multiplex_memory::read_mask(mask)?)
    };
    let result = mochios_posix_client::multiplex::with_signal_mask(
        mask,
        |value| service_signal_mask(control, posix_protocol::SIGNAL_MASK_SET, value),
        || {
            if has_signals {
                drain_pending_signals()?;
            }
            operation(control, caught)
        },
    );
    // The helper attempts restoration even on EINTR/EBADF. A failed mask RPC
    // is propagated, never treated as successful restoration.
    // Deliver any signals newly unblocked by restoration.
    if has_signals {
        drain_pending_signals()?;
    }
    result
}

#[unsafe(no_mangle)]
pub extern "C" fn pselect(
    nfds: c_int,
    readfds: *mut FdSet,
    writefds: *mut FdSet,
    exceptfds: *mut FdSet,
    timeout: *const NewlibTimespec,
    mask: *const u64,
) -> c_int {
    pthread_testcancel();
    let result = timespec_deadline(timeout).and_then(|deadline| {
        masked_multiplex(mask, |control, caught| {
            select_with_deadline(
                nfds, readfds, writefds, exceptfds, deadline, control, caught,
            )
        })
    });
    pthread_testcancel();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn ppoll(
    fds: *mut PollFd,
    nfds: u32,
    timeout: *const NewlibTimespec,
    mask: *const u64,
) -> c_int {
    pthread_testcancel();
    let result = timespec_deadline(timeout).and_then(|deadline| {
        masked_multiplex(mask, |control, caught| {
            poll_with_deadline(fds, nfds, deadline, control, caught)
        })
    });
    pthread_testcancel();
    result_with_errno(result, -1)
}

fn suspend_with_signal_mask(mask: *const u64) -> Result<c_int, c_int> {
    masked_multiplex(mask, |control, caught| {
        wait_for_multiplex(&mut [], syscall::HANDLE_WAIT_INFINITE, control, caught)?;
        // No objects and no deadline can never complete successfully.
        // Keep a broken backend visible instead of reporting a fake signal.
        Err(EIO)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn pause() -> c_int {
    pthread_testcancel();
    let result = suspend_with_signal_mask(ptr::null());
    pthread_testcancel();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn sigsuspend(mask: *const u64) -> c_int {
    pthread_testcancel();
    if mask.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = suspend_with_signal_mask(mask);
    pthread_testcancel();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn getgroups(gidsetsize: c_int, grouplist: *mut groups::Gid) -> c_int {
    let result = (|| -> Result<c_int, c_int> {
        let capacity = usize::try_from(gidsetsize).map_err(|_| EINVAL)?;
        if capacity != 0 && grouplist.is_null() {
            return Err(EFAULT);
        }
        let mut groups = [0u32; posix_protocol::MAX_SUPPLEMENTARY_GROUPS];
        let count = posix_client()
            .and_then(|client| client.get_groups(&mut groups))
            .map_err(map_posix_client_error)?;
        if capacity == 0 {
            return c_int::try_from(count).map_err(|_| EOVERFLOW);
        }
        if capacity < count {
            return Err(EINVAL);
        }
        groups_memory::write(grouplist, &groups[..count])?;
        c_int::try_from(count).map_err(|_| EOVERFLOW)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn setgroups(ngroups: c_int, grouplist: *const groups::Gid) -> c_int {
    let result = (|| -> Result<c_int, c_int> {
        let count = usize::try_from(ngroups).map_err(|_| EINVAL)?;
        if count > posix_protocol::MAX_SUPPLEMENTARY_GROUPS {
            return Err(EINVAL);
        }
        if count != 0 && grouplist.is_null() {
            return Err(EFAULT);
        }
        let mut groups = [0u32; posix_protocol::MAX_SUPPLEMENTARY_GROUPS];
        groups_memory::read(grouplist, &mut groups[..count])?;
        posix_client()
            .and_then(|client| client.set_groups(&groups[..count]))
            .map_err(map_posix_client_error)?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn umask(mask: u32) -> u32 {
    match posix_client().and_then(|client| client.set_umask(mask)) {
        Ok(previous) => previous,
        Err(error) => {
            set_errno(map_posix_client_error(error));
            0
        }
    }
}

fn credential_id(select: impl FnOnce(posix_protocol::SessionInfo) -> u32) -> credentials::Id {
    let result = posix_client()
        .and_then(|client| client.session_info())
        .map(select)
        .map_err(map_posix_client_error);
    credentials::finish(result, EOVERFLOW, set_errno)
}

#[unsafe(no_mangle)]
pub extern "C" fn getuid() -> credentials::Id {
    credential_id(|session| session.real_uid)
}

#[unsafe(no_mangle)]
pub extern "C" fn geteuid() -> credentials::Id {
    credential_id(|session| session.effective_uid)
}

#[unsafe(no_mangle)]
pub extern "C" fn getgid() -> credentials::Id {
    credential_id(|session| session.real_gid)
}

#[unsafe(no_mangle)]
pub extern "C" fn getegid() -> credentials::Id {
    credential_id(|session| session.effective_gid)
}

#[unsafe(no_mangle)]
pub extern "C" fn setgid(gid: credentials::Id) -> c_int {
    let result = posix_client()
        .map_err(map_posix_client_error)
        .and_then(|client| client.set_gid(u32::from(gid)).map_err(map_posix_client_error))
        .map(|_| 0);
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn setegid(gid: credentials::Id) -> c_int {
    let result = posix_client()
        .map_err(map_posix_client_error)
        .and_then(|client| {
            client
                .set_effective_gid(u32::from(gid))
                .map_err(map_posix_client_error)
        })
        .map(|_| 0);
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn setuid(uid: credentials::Id) -> c_int {
    let result = posix_client()
        .map_err(map_posix_client_error)
        .and_then(|client| client.set_uid(u32::from(uid)).map_err(map_posix_client_error))
        .map(|_| 0);
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn seteuid(uid: credentials::Id) -> c_int {
    let result = posix_client()
        .map_err(map_posix_client_error)
        .and_then(|client| {
            client
                .set_effective_uid(u32::from(uid))
                .map_err(map_posix_client_error)
        })
        .map(|_| 0);
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn setreuid(real: credentials::Id, effective: credentials::Id) -> c_int {
    let result = posix_client()
        .map_err(map_posix_client_error)
        .and_then(|client| {
            client
                .set_real_effective_uid(
                    credentials::update_id(real),
                    credentials::update_id(effective),
                )
                .map_err(map_posix_client_error)
        })
        .map(|_| 0);
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn setregid(real: credentials::Id, effective: credentials::Id) -> c_int {
    let result = posix_client()
        .map_err(map_posix_client_error)
        .and_then(|client| {
            client
                .set_real_effective_gid(
                    credentials::update_id(real),
                    credentials::update_id(effective),
                )
                .map_err(map_posix_client_error)
        })
        .map(|_| 0);
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn faccessat(dirfd: c_int, path: *const c_char, mode: c_int, flags: c_int) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(path_io::access(dirfd, path, mode, flags).map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn access(path: *const c_char, mode: c_int) -> c_int {
    faccessat(-2, path, mode, 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn eaccess(path: *const c_char, mode: c_int) -> c_int {
    faccessat(-2, path, mode, 1)
}

#[unsafe(no_mangle)]
pub extern "C" fn euidaccess(path: *const c_char, mode: c_int) -> c_int {
    eaccess(path, mode)
}

#[unsafe(no_mangle)]
pub extern "C" fn chmod(path: *const c_char, mode: u32) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = chmod_posix_at(-2, path, mode).map(|_| 0);
    result_with_errno(result, -1)
}

fn chmod_posix_at(dirfd: c_int, path: *const c_char, mode: u32) -> Result<(), c_int> {
    path_io::chmod(dirfd, path, mode)
}

#[unsafe(no_mangle)]
pub extern "C" fn fchmodat(dirfd: c_int, path: *const c_char, mode: u32, flags: c_int) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    if flags != 0 {
        set_errno(EINVAL);
        return -1;
    }
    result_with_errno(chmod_posix_at(dirfd, path, mode).map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn fchmod(fd: c_int, mode: u32) -> c_int {
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            if !matches!(
                entry.handle.kind,
                FdKind::ObjectFile
                    | FdKind::ObjectSpecial
                    | FdKind::ObjectTerminalFile
                    | FdKind::ObjectDirectory
            ) {
                return Err(EBADF);
            }
            let client = posix_client().map_err(map_posix_client_error)?;
            client
                .fchmod(
                    ObjectHandleAttachment {
                        handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                        rights: entry.rights,
                    },
                    mode,
                )
                .map_err(map_posix_client_error)?;
            Ok(0)
        },
    );
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn chown(path: *const c_char, uid: u32, gid: u32) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(chown_posix_at(-2, path, uid, gid, 0).map(|_| 0), -1)
}

fn chown_posix_at(
    dirfd: c_int,
    path: *const c_char,
    uid: u32,
    gid: u32,
    flags: c_int,
) -> Result<(), c_int> {
    let protocol_flags = match u64::try_from(flags).map_err(|_| EINVAL)? {
        0 => 0,
        AT_SYMLINK_NOFOLLOW => posix_protocol::CHOWN_NOFOLLOW,
        _ => return Err(EINVAL),
    };
    path_io::chown(dirfd, path, uid, gid, protocol_flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn lchown(path: *const c_char, uid: u32, gid: u32) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(
        chown_posix_at(-2, path, uid, gid, AT_SYMLINK_NOFOLLOW as c_int).map(|_| 0),
        -1,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn fchownat(
    dirfd: c_int,
    path: *const c_char,
    uid: u32,
    gid: u32,
    flags: c_int,
) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(chown_posix_at(dirfd, path, uid, gid, flags).map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn fchown(fd: c_int, uid: u32, gid: u32) -> c_int {
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            if !matches!(
                entry.handle.kind,
                FdKind::ObjectFile
                    | FdKind::ObjectSpecial
                    | FdKind::ObjectTerminalFile
                    | FdKind::ObjectDirectory
            ) {
                return Err(EBADF);
            }
            let client = posix_client().map_err(map_posix_client_error)?;
            client
                .fchown(
                    ObjectHandleAttachment {
                        handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                        rights: entry.rights,
                    },
                    uid,
                    gid,
                )
                .map_err(map_posix_client_error)?;
            Ok(0)
        },
    );
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn utimensat(
    dirfd: c_int,
    path: *const c_char,
    times: *const Timespec,
    flags: c_int,
) -> c_int {
    result_with_errno(file_time::at(dirfd, path, times, flags).map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn futimens(fd: c_int, times: *const Timespec) -> c_int {
    result_with_errno(file_time::fd(fd, times).map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn setpgid(pid: c_int, pgid: c_int) -> c_int {
    let result = posix_client()
        .map_err(map_posix_client_error)
        .and_then(|client| {
            client
                .set_process_group(pid as i64, pgid as i64)
                .map_err(map_posix_client_error)
        });
    result_with_errno(result.map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn setpgrp() -> c_int {
    setpgid(0, 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn setsid() -> c_int {
    let result = posix_client()
        .map_err(map_posix_client_error)
        .and_then(|client| client.create_session().map_err(map_posix_client_error))
        .and_then(|session| c_int::try_from(session).map_err(|_| EOVERFLOW));
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn chroot(path: *const c_char) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = path_io::chroot(path);
    result_with_errno(result.map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn opendir(path: *const c_char) -> *mut c_void {
    if path.is_null() {
        set_errno(EFAULT);
        return ptr::null_mut();
    }

    result_with_errno(directory_io::open(path), ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn fdopendir(fd: c_int) -> *mut c_void {
    result_with_errno(directory_io::adopt(fd), ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn dirfd(dirp: *mut c_void) -> c_int {
    if dirp.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let stream = unsafe { &*(dirp as *mut DirStream) };
    stream.fd
}

#[unsafe(no_mangle)]
pub extern "C" fn telldir(dirp: *mut c_void) -> core::ffi::c_long {
    if dirp.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(
        directory_io::tell(unsafe { &mut *dirp.cast::<DirStream>() }),
        -1,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn seekdir(dirp: *mut c_void, position: core::ffi::c_long) {
    if dirp.is_null() {
        set_errno(EFAULT);
        return;
    }
    if let Err(error) = directory_io::seek(unsafe { &mut *dirp.cast::<DirStream>() }, position) {
        set_errno(error);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rewinddir(dirp: *mut c_void) {
    if dirp.is_null() {
        set_errno(EFAULT);
        return;
    }
    if let Err(error) = directory_io::rewind(unsafe { &mut *dirp.cast::<DirStream>() }) {
        set_errno(error);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn closedir(dirp: *mut c_void) -> c_int {
    if dirp.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    unsafe { directory_io::close(dirp.cast()) }
}

#[unsafe(no_mangle)]
pub extern "C" fn readdir_r(
    dirp: *mut c_void,
    entry: *mut NewlibDirent,
    result: *mut *mut NewlibDirent,
) -> c_int {
    if dirp.is_null() || entry.is_null() || result.is_null() {
        set_errno(EFAULT);
        return EFAULT;
    }

    let stream = unsafe { &mut *(dirp as *mut DirStream) };
    match next_dirent(stream) {
        Ok(Some(dirent)) => unsafe {
            ptr::write(entry, dirent);
            ptr::write(result, entry);
            0
        },
        Ok(None) => unsafe {
            set_errno(0);
            ptr::write(result, ptr::null_mut());
            0
        },
        Err(errno_value) => {
            set_errno(errno_value);
            errno_value
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn readdir(dirp: *mut c_void) -> *mut NewlibDirent {
    if dirp.is_null() {
        set_errno(EFAULT);
        return ptr::null_mut();
    }

    let stream = unsafe { &mut *(dirp as *mut DirStream) };
    match next_dirent(stream) {
        Ok(Some(dirent)) => {
            stream.current = dirent;
            ptr::addr_of_mut!(stream.current)
        }
        Ok(None) => {
            set_errno(0);
            ptr::null_mut()
        }
        Err(errno_value) => {
            set_errno(errno_value);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            if !matches!(
                entry.handle.kind,
                FdKind::ObjectFile | FdKind::ObjectSpecial | FdKind::ObjectSharedMemory
            ) {
                return Err(ESPIPE);
            }
            let basis = match whence {
                0 => syscall::HANDLE_SEEK_START,
                1 => syscall::HANDLE_SEEK_CURRENT,
                2 => syscall::HANDLE_SEEK_END,
                _ => return Err(EINVAL),
            };
            let next = syscall_errno(syscall::raw_syscall3(
                syscall::SyscallNumber::HandleSeek,
                entry.handle.lower_handle,
                offset as u64,
                basis,
            ))?;
            Ok(next as i64)
        },
    );
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn lseek(fd: c_int, offset: i64, whence: c_int) -> i64 {
    _lseek(fd, offset, whence)
}

#[unsafe(no_mangle)]
pub extern "C" fn _fsync(fd: c_int) -> c_int {
    result_with_errno(sync_file_descriptor(fd), -1)
}

fn sync_file_descriptor(fd: c_int) -> Result<c_int, c_int> {
    io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            if entry.handle.kind == FdKind::ObjectTerminalFile {
                return Err(EINVAL);
            }
            if !matches!(
                entry.handle.kind,
                FdKind::ObjectFile | FdKind::ObjectSpecial | FdKind::ObjectDirectory
            ) {
                return Err(EBADF);
            }
            let client = posix_client().map_err(map_posix_client_error)?;
            client
                .fsync(ObjectHandleAttachment {
                    handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                    rights: entry.rights,
                })
                .map_err(map_posix_client_error)?;
            Ok(0)
        },
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn fsync(fd: c_int) -> c_int {
    _fsync(fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn fdatasync(fd: c_int) -> c_int {
    result_with_errno(sync_file_descriptor(fd), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn _ftruncate(fd: c_int, length: i64) -> c_int {
    if length < 0 {
        set_errno(EINVAL);
        return -1;
    }
    result_with_errno(file_mutation::ftruncate(fd, length as u64), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn ftruncate(fd: c_int, length: i64) -> c_int {
    _ftruncate(fd, length)
}

#[unsafe(no_mangle)]
pub extern "C" fn truncate(path: *const c_char, length: i64) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    if length < 0 {
        set_errno(EINVAL);
        return -1;
    }
    result_with_errno(file_mutation::truncate(path, length as u64), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn _fstat(fd: c_int, stat_buf: *mut c_void) -> c_int {
    if stat_buf.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            if entry.handle.kind == FdKind::ObjectSharedMemory {
                let status = shared_memory::stat(**entry)?;
                return stat_output::write(stat_buf, &status);
            }
            if entry.handle.kind.is_socket() {
                let status = socket::stat(**entry)?;
                return stat_output::write(stat_buf, &status);
            }
            if matches!(
                entry.handle.kind,
                FdKind::ObjectFile
                    | FdKind::ObjectSpecial
                    | FdKind::ObjectTerminalFile
                    | FdKind::ObjectDirectory
            ) {
                let handle = u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?;
                let client = posix_client().map_err(map_posix_client_error)?;
                let status = client
                    .fstat(ObjectHandleAttachment {
                        handle,
                        rights: entry.rights,
                    })
                    .map_err(map_posix_client_error)?;
                let translated = translate_posix_stat(&status)?;
                return stat_output::write(stat_buf, &translated);
            }
            if matches!(
                entry.handle.kind,
                FdKind::ObjectStreamRead | FdKind::ObjectStreamWrite
            ) {
                return stat_output::write(stat_buf, &stream_stat());
            }
            if entry.handle.kind == FdKind::ObjectPty {
                return stat_output::write(stat_buf, &pty_stat());
            }
            Err(EBADF)
        },
    );
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn fstat(fd: c_int, stat_buf: *mut c_void) -> c_int {
    _fstat(fd, stat_buf)
}

fn stat_with_flags(path: *const c_char, stat_buf: *mut c_void, flags: u64) -> c_int {
    stat_at_with_flags(-2, path, stat_buf, flags)
}

fn stat_at_with_flags(
    dirfd: c_int,
    path: *const c_char,
    stat_buf: *mut c_void,
    flags: u64,
) -> c_int {
    if path.is_null() || stat_buf.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = (|| {
        let translated = file_metadata::at(dirfd, path, flags)?;
        stat_output::write(stat_buf, &translated)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn fstatat(
    dirfd: c_int,
    path: *const c_char,
    stat_buf: *mut c_void,
    flags: c_int,
) -> c_int {
    stat_at_with_flags(dirfd, path, stat_buf, flags as u64)
}

#[unsafe(no_mangle)]
pub extern "C" fn _stat(path: *const c_char, stat_buf: *mut c_void) -> c_int {
    stat_with_flags(path, stat_buf, 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn stat(path: *const c_char, stat_buf: *mut c_void) -> c_int {
    _stat(path, stat_buf)
}

#[unsafe(no_mangle)]
pub extern "C" fn _lstat(path: *const c_char, stat_buf: *mut c_void) -> c_int {
    stat_with_flags(path, stat_buf, AT_SYMLINK_NOFOLLOW)
}

#[unsafe(no_mangle)]
pub extern "C" fn lstat(path: *const c_char, stat_buf: *mut c_void) -> c_int {
    _lstat(path, stat_buf)
}

#[unsafe(no_mangle)]
pub extern "C" fn _isatty(fd: c_int) -> c_int {
    let result = io_resources::with(|| with_fd_entry(fd), |entry| {
        if matches!(
            entry.handle.kind,
            FdKind::Stdin | FdKind::Stdout | FdKind::Stderr
        ) {
            return Ok(1);
        }
        terminal_attributes(**entry)?;
        Ok(1)
    });
    result_with_errno(result, 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn isatty(fd: c_int) -> c_int {
    _isatty(fd)
}

#[unsafe(no_mangle)]
pub extern "C" fn tcgetattr(fd: c_int, termios: *mut NewlibTermios) -> c_int {
    if termios.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            let attributes = terminal_attributes(**entry)?;
            terminal_memory::write_attributes(termios, terminal_attributes_to_newlib(attributes))?;
            Ok(0)
        },
    );
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn tcsetattr(fd: c_int, action: c_int, termios: *const NewlibTermios) -> c_int {
    if termios.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = io_resources::with_initialized(
        || Ok((with_fd_entry(fd)?, None)),
        |(_, attributes)| {
            *attributes = Some(terminal_memory::read_attributes(termios)?);
            Ok(())
        },
        |(entry, attributes)| {
            set_terminal_attributes(**entry, action, attributes.unwrap())?;
            Ok(0)
        },
    );
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn tcdrain(fd: c_int) -> c_int {
    pthread_testcancel();
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            loop {
                match terminal_control(**entry, posix_protocol::PTY_CONTROL_DRAIN, &[], &mut []) {
                    Ok(0) => return Ok(0),
                    Ok(_) => return Err(EIO),
                    Err(EAGAIN) => {
                        let _ = wait_for_handle(
                            **entry,
                            syscall::HANDLE_SIGNAL_IDLE | syscall::HANDLE_SIGNAL_PEER_CLOSED,
                        )?;
                    }
                    Err(errno) => return Err(errno),
                }
            }
        },
    );
    finish_io_cancellation(result_with_errno(result, -1)) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn tcflush(fd: c_int, queue_selector: c_int) -> c_int {
    let flags = match queue_selector {
        TCIFLUSH => posix_protocol::TERMINAL_FLUSH_INPUT,
        TCOFLUSH => posix_protocol::TERMINAL_FLUSH_OUTPUT,
        TCIOFLUSH => posix_protocol::TERMINAL_FLUSH_ALL,
        _ => {
            set_errno(EINVAL);
            return -1;
        }
    };
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            let mut encoded = [0; posix_protocol::TERMINAL_FLUSH_LEN];
            posix_protocol::encode_terminal_flush(flags, &mut encoded).map_err(|_| EINVAL)?;
            match terminal_control(
                **entry,
                posix_protocol::PTY_CONTROL_FLUSH,
                &encoded,
                &mut [],
            )? {
                0 => Ok(0),
                _ => Err(EIO),
            }
        },
    );
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn tcflow(fd: c_int, action: c_int) -> c_int {
    let result = io_resources::with(
        || with_fd_entry(fd),
        |entry| {
            let action = u32::try_from(action).map_err(|_| EINVAL)?;
            let mut encoded = [0; posix_protocol::TERMINAL_FLOW_LEN];
            posix_protocol::encode_terminal_flow(action, &mut encoded).map_err(|_| EINVAL)?;
            loop {
                match terminal_control(**entry, posix_protocol::PTY_CONTROL_FLOW, &encoded, &mut [])
                {
                    Ok(0) => return Ok(0),
                    Ok(_) => return Err(EIO),
                    Err(EAGAIN) => {
                        let _ = wait_for_handle(
                            **entry,
                            syscall::HANDLE_SIGNAL_IDLE | syscall::HANDLE_SIGNAL_PEER_CLOSED,
                        )?;
                    }
                    Err(error) => return Err(error),
                }
            }
        },
    );
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn grantpt(fd: c_int) -> c_int {
    result_with_errno(terminal_grant::grant(fd), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_openpt(flags: c_int) -> c_int {
    result_with_errno(pty_master::create(flags), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn unlockpt(fd: c_int) -> c_int {
    result_with_errno(terminal_lock::unlock(fd), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn tcgetpgrp(fd: c_int) -> c_int {
    let result = io_resources::with(
        || terminal_attachment(fd),
        |(_, terminal)| {
            let group = posix_client()
                .map_err(map_posix_client_error)?
                .terminal_foreground_process_group(*terminal)
                .map_err(map_posix_client_error)?;
            c_int::try_from(group).map_err(|_| EOVERFLOW)
        },
    );
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn tcgetsid(fd: c_int) -> c_int {
    let result = io_resources::with(
        || terminal_attachment(fd),
        |(_, terminal)| {
            let session = posix_client()
                .map_err(map_posix_client_error)?
                .terminal_session_id(*terminal)
                .map_err(map_posix_client_error)?;
            c_int::try_from(session).map_err(|_| EOVERFLOW)
        },
    );
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn tcsetpgrp(fd: c_int, process_group: c_int) -> c_int {
    if process_group <= 0 {
        set_errno(EINVAL);
        return -1;
    }
    let result = io_resources::with(
        || terminal_attachment(fd),
        |(_, terminal)| {
            retry_terminal_operation(posix_protocol::SIGNAL_TTOU, || {
                posix_client()
                    .map_err(map_posix_client_error)?
                    .set_terminal_foreground_process_group(*terminal, process_group as u64)
                    .map_err(map_posix_client_error)
            })?;
            Ok(0)
        },
    );
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn login_tty(fd: c_int) -> c_int {
    let result = io_resources::with(
        || terminal_attachment(fd),
        |(_, terminal)| {
            posix_client()
                .map_err(map_posix_client_error)?
                .create_session()
                .map_err(map_posix_client_error)?;
            let client = posix_client().map_err(map_posix_client_error)?;
            client
                .acquire_controlling_terminal(*terminal)
                .map_err(map_posix_client_error)?;
            for target in 0..=2 {
                if fd != target && dup2(fd, target) < 0 {
                    let errno = unsafe { *__errno() };
                    let _ = client.release_controlling_terminal(*terminal);
                    return Err(errno);
                }
            }
            if fd > 2 && close(fd) < 0 {
                return Err(unsafe { *__errno() });
            }
            Ok(0)
        },
    );
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfgetispeed(termios: *const NewlibTermios) -> u32 {
    if termios.is_null() {
        return 0;
    }
    result_with_errno(terminal_attributes::speed(termios, true), 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfgetospeed(termios: *const NewlibTermios) -> u32 {
    if termios.is_null() {
        return 0;
    }
    result_with_errno(terminal_attributes::speed(termios, false), 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfsetispeed(termios: *mut NewlibTermios, speed: u32) -> c_int {
    result_with_errno(terminal_attributes::set_speed(termios, speed, true, false), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfsetospeed(termios: *mut NewlibTermios, speed: u32) -> c_int {
    result_with_errno(terminal_attributes::set_speed(termios, speed, false, true), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfsetspeed(termios: *mut NewlibTermios, speed: u32) -> c_int {
    result_with_errno(terminal_attributes::set_speed(termios, speed, true, true), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn cfmakeraw(termios: *mut NewlibTermios) {
    if termios.is_null() {
        return;
    }
    if let Err(error) = terminal_attributes::make_raw(termios) {
        set_errno(error);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _sbrk(increment: isize) -> *mut c_void {
    #[cfg(feature = "trace-io")]
    let trace = io_trace::growth(increment);
    let result = (|| {
        // Read before STATE: discovery is allocation-free and may be called
        // while libc owns its recursive allocator lock. Bootstrap processes
        // without a POSIX endpoint remain subject to native Capability limits.
        let data_limit = if increment > 0 && has_posix_environment()? {
            resource_policy::read(posix_protocol::RLIMIT_DATA)?.soft
        } else {
            posix_protocol::RLIM_INFINITY
        };
        let memory_limit = if increment >= 0 {
            address_space::snapshot()?
        } else {
            address_space::Limit::UNLIMITED
        };
        // The matching SDK linker script defines the complete writable image
        // span, including TLS templates, bss and alignment gaps. No dereference.
        let image_data_bytes = (ptr::addr_of!(__mochios_data_end) as usize)
            .checked_sub(ptr::addr_of!(__mochios_data_start) as usize)
            .ok_or(ENOMEM)?;
        let mut state = state();
        state
            .heap
            .adjust(increment, image_data_bytes, data_limit, memory_limit)
            .map(|old_break| old_break as *mut c_void)
    })();
    #[cfg(feature = "trace-io")]
    if let Some(trace) = trace {
        trace.finish(result.as_ref().map(|_| 0).map_err(|error| *error));
    }
    result_with_errno(result, (-1isize) as *mut c_void)
}

#[unsafe(no_mangle)]
pub extern "C" fn sbrk(increment: isize) -> *mut c_void {
    _sbrk(increment)
}

fn trim_heap_reservation() -> Result<(), c_int> {
    state().heap.trim_unused()
}

#[unsafe(no_mangle)]
pub extern "C" fn mmap(
    addr: *mut c_void,
    len: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: CLong,
) -> *mut c_void {
    let result = (|| {
        if len == 0 || offset < 0 || (offset as u64) & 4095 != 0 {
            return Err(EINVAL);
        }
        let access = mochios_posix_client::memory::native_access(prot).ok_or(EINVAL)?;
        let mapping = mochios_posix_client::memory::native_map(flags).ok_or(EINVAL)?;
        if mapping.anonymous && offset != 0 {
            return Err(EINVAL);
        }
        mapping_io::with_source(mapping.anonymous, fd, |entry| {
            let map = |backing_handle| {
                address_space::current()?
                    .map(
                        addr as u64,
                        len as u64,
                        access,
                        mapping.options,
                        backing_handle,
                        offset as u64,
                    )
                    .map(|mapped| mapped as *mut c_void)
            };
            let backing_handle = if let Some(entry) = entry {
                if entry.handle.kind == FdKind::ObjectSharedMemory {
                    let writable = mapping.options & mnu_abi::MEMORY_MAP_SHARED != 0
                        && access & mnu_abi::MEMORY_ACCESS_WRITE != 0;
                    return mapping_backing::with(entry, writable, map);
                } else {
                    if !matches!(entry.handle.kind, FdKind::ObjectFile | FdKind::ObjectSpecial) {
                        return Err(EACCES);
                    }
                    let mut required = syscall::HANDLE_RIGHT_MAP | syscall::HANDLE_RIGHT_READ;
                    if mapping.options & mnu_abi::MEMORY_MAP_SHARED != 0
                        && access & mnu_abi::MEMORY_ACCESS_WRITE != 0
                    {
                        required |= syscall::HANDLE_RIGHT_WRITE;
                    }
                    if entry.rights & required != required {
                        return Err(EACCES);
                    }
                    entry.handle.lower_handle
                }
            } else {
                0
            };
            map(backing_handle)
        })
    })();
    result_with_errno(result, MAP_FAILED)
}

#[unsafe(no_mangle)]
pub extern "C" fn munmap(addr: *mut c_void, len: usize) -> c_int {
    let result = (|| {
        if addr.is_null() {
            return Err(EINVAL);
        }
        let native_len =
            mochios_posix_client::memory::unmap_span(addr as u64, len as u64).ok_or(EINVAL)?;
        let _ = syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryUnmap,
            addr as u64,
            native_len,
        )
        .into_result()
        .map_err(|error| mochios_posix_client::memory::unmap_errno(error.raw()))?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int {
    let result = (|| {
        if addr.is_null() || (addr as usize) & (PAGE_SIZE - 1) != 0 {
            return Err(EINVAL);
        }
        let access = mochios_posix_client::memory::native_access(prot).ok_or(EINVAL)?;
        let _ = syscall::raw_syscall3(
            syscall::SyscallNumber::MemoryProtect,
            addr as u64,
            len as u64,
            access,
        )
        .into_result()
        .map_err(|error| mochios_posix_client::memory::protection_errno(error.raw()))?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn msync(addr: *mut c_void, len: usize, flags: c_int) -> c_int {
    let result = (|| {
        if addr.is_null() || len == 0 || (addr as usize) & (PAGE_SIZE - 1) != 0 {
            return Err(EINVAL);
        }
        let policy = mochios_posix_client::memory::sync_policy(flags).ok_or(EINVAL)?;
        if policy.invalidate && !policy.asynchronous {
            return memory_refresh::synchronize(addr as u64, len as u64).map(|()| 0);
        }
        // A callback must not abandon an accepted completion Handle between
        // the two native calls. No application callback is delayed during I/O:
        // deferred admission returns before the worker's provider operations.
        let _delivery = if policy.asynchronous {
            defer_native_delivery()
        } else {
            None
        };
        let result = syscall::raw_syscall3(
            syscall::SyscallNumber::MemorySync,
            addr as u64,
            len as u64,
            policy.native_options(),
        )
        .into_result()
        .map_err(|error| mochios_posix_client::memory::sync_errno(error.raw()))?;
        if policy.asynchronous {
            // POSIX exposes no completion token. Closing this reference does
            // not cancel the worker's retained backing or clear dirty data.
            close_object_handle(result as u32);
        }
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn sysconf(name: c_int) -> CLong {
    if let Some(limit) = mochios_posix_client::configuration::local_limit(name) {
        return limit as CLong;
    }
    match name {
        SC_OPEN_MAX => result_with_errno(process_fd_limit().map(CLong::from), -1),
        SC_PAGESIZE => PAGE_SIZE as CLong,
        SC_NPROCESSORS_CONF | SC_NPROCESSORS_ONLN => {
            let result = (|| {
                let mut info = syscall::ProcessorInfo::default();
                syscall_errno(syscall::raw_syscall2(
                    syscall::SyscallNumber::ProcessorDescribe,
                    (&mut info as *mut syscall::ProcessorInfo) as u64,
                    core::mem::size_of_val(&info) as u64,
                ))?;
                mochios_posix_client::configuration::processor_count(name, info)
                    .map(CLong::from)
                    .map_err(|status| mochios_posix_client::newlib_errno::from_status(i64::from(status)))
            })();
            result_with_errno(result, -1)
        }
        SC_THREAD_STACK_MIN => 16 * 1024,
        SC_GETPW_R_SIZE_MAX | SC_HOST_NAME_MAX => 256,
        _ => {
            set_errno(EINVAL);
            -1
        }
    }
}

fn process_fd_limit() -> Result<c_int, c_int> {
    let limit = resource_policy::read(posix_protocol::RLIMIT_NOFILE)?;
    Ok(limit.soft.min(MAX_FDS as u64) as c_int)
}

fn resource_limit_impl(
    process_id: c_int,
    resource: c_int,
    replacement: Option<NewlibRlimit>,
) -> Result<NewlibRlimit, c_int> {
    if resource < 0 {
        return Err(EINVAL);
    }
    if process_id == 0 && replacement.is_none() {
        return resource_policy::read(resource as u32).map(|limit| NewlibRlimit {
            rlim_cur: limit.soft,
            rlim_max: limit.hard,
        });
    }
    posix_client()
        .map_err(map_posix_client_error)?
        .resource_limit(
            process_id as i64,
            resource as u32,
            replacement.map(|limit| posix_protocol::ResourceLimit {
                soft: limit.rlim_cur,
                hard: limit.rlim_max,
            }),
        )
        .map(|limit| NewlibRlimit {
            rlim_cur: limit.soft,
            rlim_max: limit.hard,
        })
        .map_err(map_posix_client_error)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getrlimit(resource: c_int, limit: *mut NewlibRlimit) -> c_int {
    result_with_errno(resource_limit_memory::get(resource, limit), -1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setrlimit(resource: c_int, limit: *const NewlibRlimit) -> c_int {
    result_with_errno(resource_limit_memory::set(resource, limit), -1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn prlimit(
    process_id: c_int,
    resource: c_int,
    new_limit: *const NewlibRlimit,
    old_limit: *mut NewlibRlimit,
) -> c_int {
    result_with_errno(
        resource_limit_memory::exchange(process_id, resource, new_limit, old_limit),
        -1,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn _getpid() -> c_int {
    result_with_errno(
        posix_client()
            .map_err(map_posix_client_error)
            .and_then(|client| client.process_info(0).map_err(map_posix_client_error))
            .and_then(|info| c_int::try_from(info.process_id).map_err(|_| EOVERFLOW)),
        -1,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn getpid() -> c_int {
    _getpid()
}

#[unsafe(no_mangle)]
pub extern "C" fn getppid() -> c_int {
    result_with_errno(
        posix_client()
            .map_err(map_posix_client_error)
            .and_then(|client| client.process_info(0).map_err(map_posix_client_error))
            .and_then(|info| c_int::try_from(info.parent_id).map_err(|_| EOVERFLOW)),
        -1,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn getpgid(pid: c_int) -> c_int {
    result_with_errno(
        posix_client()
            .map_err(map_posix_client_error)
            .and_then(|client| {
                client
                    .process_info(pid as i64)
                    .map_err(map_posix_client_error)
            })
            .and_then(|info| c_int::try_from(info.process_group_id).map_err(|_| EOVERFLOW)),
        -1,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn getpgrp() -> c_int {
    getpgid(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn getsid(pid: c_int) -> c_int {
    result_with_errno(
        posix_client()
            .map_err(map_posix_client_error)
            .and_then(|client| {
                client
                    .process_info(pid as i64)
                    .map_err(map_posix_client_error)
            })
            .and_then(|info| c_int::try_from(info.session_id).map_err(|_| EOVERFLOW)),
        -1,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn _kill(pid: c_int, sig: c_int) -> c_int {
    if !(0..=posix_protocol::SIGNAL_MAX as c_int).contains(&sig) {
        set_errno(EINVAL);
        return -1;
    }
    result_with_errno(
        posix_client()
            .map_err(map_posix_client_error)
            .and_then(|client| {
                client
                    .send_signal(i64::from(pid), sig as u32)
                    .map_err(map_posix_client_error)
            })
            .map(|_| 0),
        -1,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn kill(pid: c_int, sig: c_int) -> c_int {
    _kill(pid, sig)
}

fn generate_thread_signal(signal: u32) -> Result<(), c_int> {
    register_current_thread().ok_or(EAGAIN)?;
    posix_client()
        .map_err(map_posix_client_error)?
        .raise_signal(signal)
        .map_err(map_posix_client_error)?;
    drain_pending_signals()
}

#[unsafe(no_mangle)]
pub extern "C" fn raise(signal: c_int) -> c_int {
    result_with_errno(
        if (0..=posix_protocol::SIGNAL_MAX as c_int).contains(&signal) {
            generate_thread_signal(signal as u32).map(|_| 0)
        } else {
            Err(EINVAL)
        },
        -1,
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigaction(
    signal: c_int,
    action: *const SignalAction,
    old_action: *mut SignalAction,
) -> c_int {
    if signal <= 0 || signal > posix_protocol::SIGNAL_MAX as c_int {
        set_errno(EINVAL);
        return -1;
    }
    if !action.is_null() && !mochios_posix_client::signal::can_change_disposition(signal as u32) {
        set_errno(EINVAL);
        return -1;
    }
    let index = signal as usize - 1;
    if action.is_null() {
        if !old_action.is_null() {
            let previous = SIGNAL_ACTIONS.lock()[index];
            return result_with_errno(
                signal_memory::write_action(old_action, previous).map(|_| 0),
                -1,
            );
        }
        return 0;
    }
    let mut replacement = match signal_memory::read_action(action) {
        Ok(value) => value,
        Err(error) => {
            set_errno(error);
            return -1;
        }
    };
    if replacement.sa_flags
        & !(SA_NOCLDSTOP | SA_NOCLDWAIT | SA_RESTART | SA_SIGINFO | SA_ONSTACK | SA_NODEFER | SA_RESETHAND)
        != 0
        || (replacement.sa_flags & (SA_NOCLDSTOP | SA_NOCLDWAIT) != 0
            && signal != posix_protocol::SIGNAL_CHLD as c_int)
    {
        set_errno(EINVAL);
        return -1;
    }
    replacement.sa_mask = mochios_posix_client::signal::sanitize_mask(replacement.sa_mask);

    let _update = SIGNAL_ACTION_UPDATE.lock();
    let previous = SIGNAL_ACTIONS.lock()[index];
    let mut options = if replacement.sa_flags & SA_NOCLDSTOP != 0 {
        posix_protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP
    } else {
        0
    };
    if replacement.sa_flags & SA_NOCLDWAIT != 0 {
        options |= posix_protocol::SIGNAL_CHILD_OPTION_NOCLDWAIT;
    }
    let kind = match replacement.handler {
        0 => posix_protocol::SIGNAL_DISPOSITION_DEFAULT,
        1 => posix_protocol::SIGNAL_DISPOSITION_IGNORE,
        usize::MAX => {
            set_errno(EINVAL);
            return -1;
        }
        _ => posix_protocol::SIGNAL_DISPOSITION_CAUGHT,
    };
    if let Err(error) = posix_client()
        .map_err(map_posix_client_error)
        .and_then(|client| {
            client
                .set_signal_disposition(posix_protocol::SignalDisposition {
                    signal: signal as u32,
                    kind,
                    child_options: options,
                })
                .map_err(map_posix_client_error)
        })
    {
        set_errno(error);
        return -1;
    }
    {
        let mut actions = SIGNAL_ACTIONS.lock();
        actions[index] = replacement;
    }
    // The service already committed. Publish the matching local handler before
    // any fallible copyout; EFAULT must not leave the two dispositions divergent.
    if !old_action.is_null() {
        return result_with_errno(
            signal_memory::write_action(old_action, previous).map(|_| 0),
            -1,
        );
    }
    0
}

fn service_signal_mask(control: &ThreadControl, operation: u32, requested: u64) -> Result<u64, c_int> {
    let previous = posix_client()
        .map_err(map_posix_client_error)?
        .thread_signal_mask(operation, requested)
        .map_err(map_posix_client_error)?;
    let requested = mochios_posix_client::signal::sanitize_mask(requested);
    let updated = match operation {
        posix_protocol::SIGNAL_MASK_SET => requested,
        posix_protocol::SIGNAL_MASK_BLOCK => previous | requested,
        posix_protocol::SIGNAL_MASK_UNBLOCK => previous & !requested,
        _ => previous,
    };
    // Only an inheritance cache; delivery/pending always use service state.
    control.signal_mask.store(updated, Ordering::Release);
    Ok(previous)
}

fn update_current_signal_mask(how: c_int, set: *const u64, old_set: *mut u64) -> Result<(), c_int> {
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let (operation, requested) = if set.is_null() {
        (posix_protocol::SIGNAL_MASK_QUERY, 0)
    } else {
        let operation = match how {
            mochios_posix_client::signal::SIGNAL_SET_MASK => posix_protocol::SIGNAL_MASK_SET,
            mochios_posix_client::signal::SIGNAL_BLOCK => posix_protocol::SIGNAL_MASK_BLOCK,
            mochios_posix_client::signal::SIGNAL_UNBLOCK => posix_protocol::SIGNAL_MASK_UNBLOCK,
            _ => return Err(EINVAL),
        };
        (operation, signal_memory::read_set(set)?)
    };
    let previous = service_signal_mask(control, operation, requested)?;
    let output = if old_set.is_null() {
        Ok(())
    } else {
        signal_memory::write_set(old_set, previous)
    };
    let updated = control.signal_mask.load(Ordering::Acquire);
    // The mask change already committed. Complete newly unblocked delivery
    // even if the old-mask copy failed, retaining that copy error for the caller.
    let delivery = if previous & !updated != 0 {
        drain_pending_signals()
    } else {
        Ok(())
    };
    output.and(delivery)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigemptyset(set: *mut u64) -> c_int {
    if set.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(signal_memory::write_set(set, 0).map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigfillset(set: *mut u64) -> c_int {
    if set.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(signal_memory::write_set(set, u64::MAX).map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigaddset(set: *mut u64, signal: c_int) -> c_int {
    let Some(bit) = mochios_posix_client::signal::newlib_set_bit(signal) else {
        set_errno(EINVAL);
        return -1;
    };
    if set.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(
        signal_memory::read_set(set)
            .and_then(|value| signal_memory::write_set(set, value | bit).map(|_| 0)),
        -1,
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigdelset(set: *mut u64, signal: c_int) -> c_int {
    let Some(bit) = mochios_posix_client::signal::newlib_set_bit(signal) else {
        set_errno(EINVAL);
        return -1;
    };
    if set.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(
        signal_memory::read_set(set)
            .and_then(|value| signal_memory::write_set(set, value & !bit).map(|_| 0)),
        -1,
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigismember(set: *const u64, signal: c_int) -> c_int {
    let Some(bit) = mochios_posix_client::signal::newlib_set_bit(signal) else {
        set_errno(EINVAL);
        return -1;
    };
    if set.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(
        signal_memory::read_set(set).map(|value| c_int::from(value & bit != 0)),
        -1,
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigprocmask(how: c_int, set: *const u64, old_set: *mut u64) -> c_int {
    result_with_errno(update_current_signal_mask(how, set, old_set).map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_sigmask(how: c_int, set: *const u64, old_set: *mut u64) -> c_int {
    match update_current_signal_mask(how, set, old_set) {
        Ok(()) => 0,
        Err(error) => error,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigpending(set: *mut u64) -> c_int {
    if set.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let _ = match register_current_thread() {
        Some(current) => current,
        None => {
            set_errno(EAGAIN);
            return -1;
        }
    };
    result_with_errno(
        posix_client()
            .map_err(map_posix_client_error)
            .and_then(|client| client.thread_pending_signals().map_err(map_posix_client_error))
            .and_then(|pending| signal_memory::write_set(set, pending).map(|_| 0)),
        -1,
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigwait(set: *const u64, selected: *mut c_int) -> c_int {
    let result = (|| {
        if set.is_null() || selected.is_null() {
            return Err(EFAULT);
        }
        let _ = register_current_thread().ok_or(EAGAIN)?;
        let mask = signal_memory::read_set(set)?;
        let client = posix_client().map_err(map_posix_client_error)?;
        loop {
            let epoch = client.thread_signal_epoch().map_err(map_posix_client_error)?;
            match client.wait_thread_signal_info_since(mask, epoch) {
                Ok(accepted) => {
                    if signal_info::prepare(accepted.signal, accepted.origin)?.is_none() {
                        continue;
                    }
                    // This signal was consumed synchronously. Do not dispatch
                    // its handler or discard it due to a later async delivery.
                    signal_memory::write_selected(selected, accepted.signal as c_int)?;
                    return Ok(());
                }
                Err(PosixClientError::Remote(posix_protocol::STATUS_EINTR)) => {
                    // Unlike waitpid, sigwait retries unrelated caught signals
                    // regardless of SA_RESTART, without unblocking its set.
                    drain_pending_signals()?;
                }
                Err(error) => return Err(map_posix_client_error(error)),
            }
        }
    })();
    // POSIX thread APIs return the error number directly, not through errno.
    result.err().unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigwaitinfo(
    set: *const u64,
    info: *mut mochios_posix_client::signal_context::SigInfo,
) -> c_int {
    result_with_errno(wait_signal_info(set, info, None), -1)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigtimedwait(
    set: *const u64,
    info: *mut mochios_posix_client::signal_context::SigInfo,
    timeout: *const NewlibTimespec,
) -> c_int {
    let result = (|| {
        let deadline = if timeout.is_null() {
            None
        } else {
            let deadline = timespec_deadline(timeout)?;
            if deadline == syscall::HANDLE_WAIT_INFINITE {
                return Err(EOVERFLOW);
            }
            Some(deadline)
        };
        wait_signal_info(set, info, deadline)
    })();
    result_with_errno(result, -1)
}

fn wait_signal_info(
    set: *const u64,
    info: *mut mochios_posix_client::signal_context::SigInfo,
    deadline: Option<u64>,
) -> Result<c_int, c_int> {
    (|| {
        if set.is_null() {
            return Err(EFAULT);
        }
        register_current_thread().ok_or(EAGAIN)?;
        let mask = signal_memory::read_set(set)?;
        let client = posix_client().map_err(map_posix_client_error)?;
        loop {
            let epoch = client.thread_signal_epoch().map_err(map_posix_client_error)?;
            let received = match deadline {
                Some(deadline) => client.wait_thread_signal_info_until(mask, epoch, deadline),
                None => client.wait_thread_signal_info_since(mask, epoch),
            };
            let accepted = match received {
                Ok(accepted) => accepted,
                Err(PosixClientError::Remote(posix_protocol::STATUS_EINTR)) => {
                    drain_pending_signals()?;
                    return Err(EINTR);
                }
                Err(error) => return Err(map_posix_client_error(error)),
            };
            let Some(prepared) = signal_info::prepare(accepted.signal, accepted.origin)? else {
                // Reuse the original absolute deadline: late deleted timers
                // cannot extend sigtimedwait indefinitely by resetting it.
                continue;
            };
            signal_memory::write_resolved_info(info, prepared.into_info()?)?;
            return Ok(accepted.signal as c_int);
        }
    })()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _signal_r(_reent: *mut c_void, signal: c_int, handler: usize) -> usize {
    let replacement = SignalAction {
        sa_flags: 0,
        sa_mask: 0,
        handler,
    };
    let mut previous = SignalAction::default_action();
    if unsafe { sigaction(signal, &replacement, &mut previous) } == 0 {
        previous.handler
    } else {
        usize::MAX
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal(signal: c_int, handler: usize) -> usize {
    unsafe { _signal_r(ptr::null_mut(), signal, handler) }
}

#[unsafe(no_mangle)]
pub extern "C" fn _init_signal_r(_reent: *mut c_void) -> c_int {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn _init_signal() -> c_int {
    0
}

fn dispatch_signal(
    delivery: posix_protocol::SignalDelivery,
    fault_info: Option<SigInfo>,
    context: &mut UContext,
    native: bool,
    preparation: &mut Preparation,
    scope: core::pin::Pin<&mut signal_scope::Scope>,
) -> Result<c_int, c_int> {
    let signal = delivery.signal as c_int;
    if signal <= 0 || signal > posix_protocol::SIGNAL_MAX as c_int {
        return Err(EINVAL);
    }
    let metadata = match fault_info {
        Some(info) => signal_info::Prepared::Ready(info),
        None => {
            let origin = match posix_client()
                .map_err(map_posix_client_error)?
                .signal_delivery_origin(delivery)
            {
                Ok(origin) => origin,
                // SIGCONT can cancel a dequeued stop before its handler or
                // default action commits. Only authoritative remote absence
                // permits skipping completion; a transport EAGAIN does not.
                Err(PosixClientError::Remote(posix_protocol::STATUS_EAGAIN)) => return Ok(4),
                Err(error) => return Err(map_posix_client_error(error)),
            };
            let Some(prepared) = signal_info::prepare(delivery.signal, origin)? else {
                return Ok(3);
            };
            prepared
        }
    };
    let action = signal_action::select(signal as u32)?;
    match action.handler {
        0 => Ok(1),
        usize::MAX => Ok(2),
        1 => Ok(3),
        _ => {
            let mut info = if action.sa_flags & SA_SIGINFO != 0 {
                Some(metadata.into_info()?)
            } else {
                None
            };
            let control = preparation.control;
            let handler_mask = mochios_posix_client::signal::handler_mask(
                signal as u32,
                action.sa_mask,
                action.sa_flags,
            )
            .ok_or(EINVAL)?;
            let previous = service_signal_mask(
                control,
                posix_protocol::SIGNAL_MASK_BLOCK,
                handler_mask,
            )?;
            context.uc_sigmask = previous;
            let original = context.uc_mcontext;
            control
                .caught_signal_generation
                .fetch_add(1, Ordering::Release);
            notify_thread_waiter(control);
            // Record the selected action before invoking it: the handler may
            // replace its own disposition, which must not change this event.
            if action.sa_flags & SA_RESTART != 0 {
                control
                    .restart_signal_generation
                    .fetch_add(1, Ordering::Release);
            } else {
                control
                    .nonrestart_signal_generation
                    .fetch_add(1, Ordering::Release);
            }
            let saved_errno = unsafe { *__errno() };
            let invoked = signal_stack::invoke(
                control, action, signal, info.as_mut(), context, native, preparation, scope,
            );
            set_errno(saved_errno);
            if let Err(error) = invoked {
                service_signal_mask(control, posix_protocol::SIGNAL_MASK_SET, previous)?;
                return Err(error);
            }
            let selected = context.uc_mcontext.checked_return(&original);
            let restore_mask = if info.is_some() && selected.is_some() {
                context.uc_sigmask
            } else {
                previous
            };
            service_signal_mask(control, posix_protocol::SIGNAL_MASK_SET, restore_mask)?;
            context.uc_mcontext = selected.unwrap_or(original);
            if selected.is_none() {
                return Err(EINVAL);
            }
            Ok(0)
        }
    }
}

fn apply_default_signal_action(delivery: posix_protocol::SignalDelivery) -> Result<(), c_int> {
    let signal = delivery.signal;
    match signal {
        posix_protocol::SIGNAL_URG
        | posix_protocol::SIGNAL_CONT
        | posix_protocol::SIGNAL_CHLD
        | posix_protocol::SIGNAL_WINCH => posix_client()
            .map_err(map_posix_client_error)?
            .complete_signal_delivery(delivery)
            .map_err(map_posix_client_error),
        posix_protocol::SIGNAL_STOP
        | posix_protocol::SIGNAL_TSTP
        | posix_protocol::SIGNAL_TTIN
        | posix_protocol::SIGNAL_TTOU => {
            let client = posix_client().map_err(map_posix_client_error)?;
            JOB_STOPS_IN_FLIGHT.fetch_add(1, Ordering::AcqRel);
            let stopped = client.report_process_stopped(delivery);
            if stopped.is_ok() {
                JOB_STOP_GENERATION.fetch_add(1, Ordering::Release);
            }
            JOB_STOPS_IN_FLIGHT.fetch_sub(1, Ordering::Release);
            let _ =
                mochios_posix_client::synchronization::wake_u32(&JOB_STOPS_IN_FLIGHT, usize::MAX);
            match stopped {
                Ok(()) => Ok(()),
                Err(PosixClientError::Remote(posix_protocol::STATUS_EAGAIN)) => Ok(()),
                Err(error) => Err(map_posix_client_error(error)),
            }
        }
        _ => {
            match posix_client()
                .map_err(map_posix_client_error)?
                .report_process_signaled(delivery)
            {
                Ok(()) => process_exit(128 + signal as c_int),
                Err(PosixClientError::Remote(posix_protocol::STATUS_EAGAIN)) => Ok(()),
                Err(error) => Err(map_posix_client_error(error)),
            }
        }
    }
}

fn drain_pending_signals() -> Result<(), c_int> {
    signal_delivery::drain()
}

fn drain_pending_signals_with_context(context: &mut UContext, native: bool) -> Result<(), c_int> {
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    if control.callback_resources.is_deferred() {
        return Ok(());
    }
    control.callback_resources.take_notification();
    loop {
        let mut preparation = Preparation::new(control)?;
        let epoch = preparation.epoch;
        let received = posix_client()
            .map_err(map_posix_client_error)
            .and_then(|client| {
                client
                    .thread_dequeue_signal_delivery()
                    .map_err(map_posix_client_error)
            });
        if FORK_EPOCH.load(Ordering::Acquire) != epoch {
            // Neither a token nor an error/empty result copied from a parent
            // describes this child's pending state. Query the child afresh.
            continue;
        }
        let delivery = received?;
        let signal = delivery.signal;
        if signal == 0 {
            return Ok(());
        }
        let mut scope = core::pin::pin!(signal_scope::Scope::new(control, delivery, epoch)?);
        let dispatched = dispatch_signal(
            delivery, None, context, native, &mut preparation, scope.as_mut(),
        );
        if FORK_EPOCH.load(Ordering::Acquire) != epoch {
            // A fork child resumes the copied handler, not its parent's
            // service-owned delivery. Only the original process may finish it.
            if preparation.started() {
                dispatched?;
            }
            continue;
        }
        let finished = match dispatched {
            Ok(0 | 3) => scope.as_mut().complete(),
            Ok(1) => apply_default_signal_action(delivery),
            Ok(4) => Ok(()), // Origin lookup confirmed cancellation; no token remains.
            result => {
                let _ = scope.as_mut().complete();
                Err(result.err().unwrap_or(EINVAL))
            }
        };
        // Do not replay a completion/default-action request in the child.
        // Its copied reply, including failure, belongs to the parent.
        if FORK_EPOCH.load(Ordering::Acquire) != epoch {
            continue;
        }
        finished?;
    }
}

extern "C" fn posix_signal_upcall(
    payload: u64,
    token: u64,
    kind: u64,
    address: u64,
    _cpu_error: u64,
    _instruction: u64,
    cause: u64,
) -> ! {
    let mut native_frame = core::pin::pin!(match signal_delivery::NativeFrame::new(token) {
        Ok(frame) => frame,
        Err(_) => process_exit(127),
    });
    if native_frame.as_mut().activate().is_err() {
        process_exit(127);
    }
    let mut context = match signal_delivery::interrupted(token) {
        Ok(context) => context,
        Err(_) => process_exit(127),
    };
    if kind == syscall::THREAD_UPCALL_KIND_EXCEPTION {
        if payload != 14 || fault_signal::deliver(cause, address as usize, &mut context).is_err() {
            process_exit(127);
        }
    } else if current_thread_control().is_some_and(|(_, control)| {
        if control.callback_resources.record_notification() {
            notify_thread_waiter(control);
            true
        } else {
            false
        }
    }) {
        // Keep the generic native notification responsive. The interrupted
        // operation must release its owned wait position before C can run.
    } else {
        if drain_pending_signals_with_context(&mut context, true).is_err() {
            process_exit(127);
        }
    }
    signal_delivery::resume(&context, native_frame.as_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn __sigtramp_r(_reent: *mut c_void, signal: c_int) -> c_int {
    result_with_errno(generate_thread_signal(signal as u32).map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn __sigtramp(signal: c_int) -> c_int {
    result_with_errno(generate_thread_signal(signal as u32).map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_kill(thread: Pthread, signal: c_int) -> c_int {
    let result = (|| {
        if !(0..=posix_protocol::SIGNAL_MAX as c_int).contains(&signal) {
            return Err(EINVAL);
        }
        register_current_thread().ok_or(EAGAIN)?;
        let control = thread_control(thread).ok_or(ESRCH)?;
        let current = current_thread_control().is_some_and(|(current, _)| current == thread);
        loop {
            let state = control.state.load(Ordering::Acquire);
            if state == THREAD_STARTING && !current {
                native_mutex_wait(&control.state, state);
                continue;
            }
            if state != THREAD_RUNNING && !(current && state == THREAD_STARTING) {
                return Err(ESRCH);
            }
            break;
        }
        {
            let reference = thread_reference::snapshot(
                thread,
                syscall::HANDLE_RIGHT_WAIT
                    | syscall::HANDLE_RIGHT_SIGNAL
                    | syscall::HANDLE_RIGHT_TRANSFER,
            )?;
            posix_client()
                .map_err(map_posix_client_error)?
                .send_thread_signal(
                    signal as u32,
                    ObjectHandleAttachment {
                        handle: reference.handle(),
                        rights: syscall::HANDLE_RIGHT_WAIT | syscall::HANDLE_RIGHT_SIGNAL,
                    },
                )
                .map_err(map_posix_client_error)?;
        }
        if current {
            drain_pending_signals()?;
        }
        Ok(())
    })();
    result.err().unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn _times(buf: *mut Tms) -> u64 {
    let result = (|| {
        use mochios_posix_client::accounting::clock_ticks;
        if buf.is_null() {
            return elapsed_clock_ticks();
        }
        let own = syscall::execution::usage(None)
            .map_err(|error| map_kernel_errno(error.raw()))?;
        let child = posix_client().map_err(map_posix_client_error)?
            .waited_child_cpu_usage().map_err(map_posix_client_error)?;
        let value = Tms {
            tms_utime: clock_ticks(u128::from(own.user_ticks), own.ticks_per_second)?,
            tms_stime: clock_ticks(u128::from(own.kernel_ticks), own.ticks_per_second)?,
            tms_cutime: clock_ticks(child.user_ticks, child.ticks_per_second)?,
            tms_cstime: clock_ticks(child.kernel_ticks, child.ticks_per_second)?,
        };
        let elapsed = elapsed_clock_ticks()?;
        // No partial output on an unavailable service, bad metadata, or overflow.
        time_memory::write_accounting(buf, value)?;
        Ok(elapsed)
    })();
    result_with_errno(result, u64::MAX)
}

fn elapsed_clock_ticks() -> Result<u64, c_int> {
    let mut instant = mnu_abi::ClockInstant::default();
    syscall_errno(syscall::raw_syscall2(
        syscall::SyscallNumber::ClockRead,
        mnu_abi::ClockId::Monotonic as u64,
        (&mut instant as *mut mnu_abi::ClockInstant) as u64,
    ))?;
    if instant.reserved != 0 {
        return Err(EIO);
    }
    mochios_posix_client::accounting::elapsed_clock_ticks(instant.seconds, instant.nanoseconds)
}

#[unsafe(no_mangle)]
pub extern "C" fn clock() -> u64 {
    let result = syscall::execution::usage(None)
        .map_err(|error| map_kernel_errno(error.raw()))
        .and_then(|usage| {
            mochios_posix_client::accounting::clock_ticks(
                u128::from(usage.user_ticks) + u128::from(usage.kernel_ticks),
                usage.ticks_per_second,
            )
        });
    // CPU-only ISO C clock stays native, including bootstrap without POSIX IPC.
    result_with_errno(result, u64::MAX)
}

#[unsafe(no_mangle)]
pub extern "C" fn times(buf: *mut Tms) -> u64 {
    _times(buf)
}

#[unsafe(no_mangle)]
pub extern "C" fn getrandom(buffer: *mut c_void, length: usize, flags: u32) -> isize {
    if !mochios_posix_client::random::flags_are_supported(flags) {
        set_errno(EINVAL);
        return -1;
    }
    if length != 0 && buffer.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(
        syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::RandomFill,
            buffer as u64,
            length as u64,
        ))
        .and_then(|written| isize::try_from(written).map_err(|_| EOVERFLOW)),
        -1,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn getentropy(buffer: *mut c_void, length: usize) -> c_int {
    if length > 256 {
        set_errno(EIO);
        return -1;
    }
    if length != 0 && buffer.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    if (buffer as usize).checked_add(length).is_none() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(
        mochios_posix_client::random::fill_entropy(length, |offset, remaining| {
            // Caller addresses stay integers until the native copy validates
            // them; a non-null C pointer is not a Rust allocation guarantee.
            let destination = (buffer as usize).checked_add(offset).ok_or(EFAULT)?;
            syscall_errno(syscall::raw_syscall2(
                syscall::SyscallNumber::RandomFill,
                destination as u64,
                remaining as u64,
            ))
            .and_then(|count| usize::try_from(count).map_err(|_| EIO))
        })
        .map(|()| 0),
        -1,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn clock_getres(clock_id: u64, resolution: *mut Timespec) -> c_int {
    if mochios_posix_client::process_clock::target(clock_id).is_some() {
        return result_with_errno(process_clock::resolution(clock_id, resolution), -1);
    }
    if thread_clock::is_id(clock_id) {
        return result_with_errno(thread_clock::resolution(clock_id, resolution), -1);
    }
    let native_clock = match c_int::try_from(clock_id)
        .ok()
        .and_then(mochios_posix_client::time::classify_clock_id)
    {
        Some(mochios_posix_client::time::ClockKind::Realtime) => mnu_abi::ClockId::Realtime,
        Some(mochios_posix_client::time::ClockKind::Monotonic) => mnu_abi::ClockId::Monotonic,
        Some(mochios_posix_client::time::ClockKind::ProcessCpu) => mnu_abi::ClockId::ProcessCpu,
        Some(mochios_posix_client::time::ClockKind::ThreadCpu) => mnu_abi::ClockId::ThreadCpu,
        _ => {
            set_errno(EINVAL);
            return -1;
        }
    };
    let mut info = mnu_abi::ClockInfo::default();
    let result = syscall_errno(syscall::raw_syscall3(
        syscall::SyscallNumber::ClockDescribe,
        native_clock as u64,
        (&mut info as *mut mnu_abi::ClockInfo) as u64,
        core::mem::size_of::<mnu_abi::ClockInfo>() as u64,
    ))
    .and_then(|_| {
        let (seconds, nanoseconds) =
            mochios_posix_client::time::clock_resolution(info.quantum_nanoseconds)?;
        // POSIX permits a NULL result while still checking clock validity.
        if !resolution.is_null() {
            time_memory::write_timespec(
                resolution,
                Timespec { tv_sec: seconds, tv_nsec: nanoseconds },
            )?;
        }
        Ok(0)
    });
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn clock_gettime(clock_id: u64, tp: *mut Timespec) -> c_int {
    if tp.is_null() {
        set_errno(EFAULT);
        return -1;
    }

    if mochios_posix_client::process_clock::target(clock_id).is_some() {
        return result_with_errno(process_clock::read(clock_id, tp), -1);
    }
    if thread_clock::is_id(clock_id) {
        return result_with_errno(thread_clock::read(clock_id, tp), -1);
    }

    let native_clock = match c_int::try_from(clock_id)
        .ok()
        .and_then(mochios_posix_client::time::classify_clock_id)
    {
        Some(mochios_posix_client::time::ClockKind::Realtime) => mnu_abi::ClockId::Realtime,
        Some(mochios_posix_client::time::ClockKind::Monotonic) => mnu_abi::ClockId::Monotonic,
        Some(mochios_posix_client::time::ClockKind::ProcessCpu) => mnu_abi::ClockId::ProcessCpu,
        Some(mochios_posix_client::time::ClockKind::ThreadCpu) => mnu_abi::ClockId::ThreadCpu,
        _ => {
            set_errno(EINVAL);
            return -1;
        }
    };

    let mut instant = mnu_abi::ClockInstant::default();
    let result = syscall_errno(syscall::raw_syscall2(
        syscall::SyscallNumber::ClockRead,
        native_clock as u64,
        (&mut instant as *mut mnu_abi::ClockInstant) as u64,
    ))
    .and_then(|_| {
        if instant.nanoseconds >= 1_000_000_000 || instant.reserved != 0 {
            return Err(EIO);
        }
        let seconds = i64::try_from(instant.seconds).map_err(|_| EOVERFLOW)?;
        time_memory::write_timespec(
            tp,
            Timespec {
                tv_sec: seconds,
                tv_nsec: i64::from(instant.nanoseconds),
            },
        )?;
        Ok(0)
    });
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn sched_yield() -> c_int {
    result_with_errno(
        syscall_errno(syscall::raw_syscall0(syscall::SyscallNumber::ThreadYield)).map(|_| 0),
        -1,
    )
}

/// Process-wide elapsed-time alarm; never a cancellation point.
#[unsafe(no_mangle)]
pub extern "C" fn alarm(seconds: u32) -> u32 {
    let result = posix_client()
        .map_err(map_posix_client_error)
        .and_then(|client| client.alarm(seconds).map_err(map_posix_client_error));
    match result {
        Ok(previous) => previous,
        Err(error) => {
            set_errno(error);
            0
        }
    }
}

/// Unlike nanosleep, POSIX clock_nanosleep returns an error number directly.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clock_nanosleep(
    clock_id: u64,
    flags: c_int,
    request: *const Timespec,
    remaining: *mut Timespec,
) -> c_int {
    pthread_testcancel();
    let saved_errno = unsafe { *__errno() };
    let result = (|| {
        use mochios_posix_client::time::{ClockKind, ClockSleep, SleepObservation, observe_sleep};
        if request.is_null() {
            return Err(EFAULT);
        }
        let request = time_memory::read_timespec(request)?;
        if let Some(process) = cpu_sleep::target(clock_id) {
            return cpu_sleep::sleep(process, flags, request, remaining);
        }
        if thread_clock::is_id(clock_id) {
            return cpu_sleep::sleep_thread(clock_id, flags, request, remaining);
        }
        let clock_id = c_int::try_from(clock_id).map_err(|_| EINVAL)?;
        let spec = ClockSleep::parse(clock_id, flags, request.tv_sec, request.tv_nsec)?;
        if !spec.absolute && spec.nanoseconds == 0 {
            return Ok(());
        }
        let (_, control) = register_current_thread().ok_or(EAGAIN)?;
        let generation = control.caught_signal_generation.load(Ordering::Acquire);
        let started = monotonic_nanoseconds()?;
        let relative_deadline = if spec.absolute {
            0
        } else {
            started.checked_add(spec.nanoseconds).ok_or(EOVERFLOW)?
        };
        loop {
            // Snapshot before checking either cause. A notification arriving
            // between the checks and WaitOnAddress changes the expected word,
            // so the native wait cannot lose a cancellation or caught signal.
            let wake = control.wait_generation.load(Ordering::Acquire);
            pthread_testcancel();
            // Read the selected absolute clock again after each wake. Today
            // native realtime is read-only; a future clock-adjustment mechanism
            // must also wake absolute-clock waiters instead of polling here.
            let now = monotonic_nanoseconds()?;
            let duration = if spec.absolute {
                let selected_now = match spec.clock {
                    ClockKind::Monotonic => now,
                    ClockKind::Realtime => {
                        let mut instant = mnu_abi::ClockInstant::default();
                        syscall_errno(syscall::raw_syscall2(
                            syscall::SyscallNumber::ClockRead,
                            mnu_abi::ClockId::Realtime as u64,
                            (&mut instant as *mut mnu_abi::ClockInstant) as u64,
                        ))?;
                        if instant.nanoseconds >= 1_000_000_000 || instant.reserved != 0 {
                            return Err(EIO);
                        }
                        instant
                            .seconds
                            .checked_mul(1_000_000_000)
                            .and_then(|value| value.checked_add(u64::from(instant.nanoseconds)))
                            .ok_or(EOVERFLOW)?
                    }
                    _ => return Err(EINVAL),
                };
                spec.remaining(selected_now)
            } else {
                relative_deadline.saturating_sub(now)
            };
            let deadline = now.checked_add(duration).ok_or(EOVERFLOW)?;
            match observe_sleep(
                deadline,
                now,
                generation,
                control.caught_signal_generation.load(Ordering::Acquire),
            ) {
                SleepObservation::Complete => {
                    pthread_testcancel();
                    return Ok(());
                }
                SleepObservation::Interrupted {
                    remaining_nanoseconds,
                } => {
                    if !spec.absolute && !remaining.is_null() {
                        time_memory::write_timespec(
                            remaining,
                            Timespec {
                                tv_sec: (remaining_nanoseconds / 1_000_000_000) as i64,
                                tv_nsec: (remaining_nanoseconds % 1_000_000_000) as i64,
                            },
                        )?;
                    }
                    return Err(EINTR);
                }
                SleepObservation::Waiting => {}
            }
            mochios_posix_client::synchronization::wait_u32(
                &control.wait_generation,
                wake,
                deadline,
            )
            .map_err(|error| map_kernel_errno(error.raw()))?;
        }
    })();
    // A failed native wait is still a return from a cancellation point.
    pthread_testcancel();
    set_errno(saved_errno);
    result.err().unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sleep(seconds: u32) -> u32 {
    let saved_errno = unsafe { *__errno() };
    let request = Timespec {
        tv_sec: i64::from(seconds),
        tv_nsec: 0,
    };
    let mut remaining = Timespec {
        tv_sec: i64::from(seconds),
        tv_nsec: 0,
    };
    // Reuse the cancellable monotonic wait, not process-wide alarm state.
    let result = unsafe { nanosleep(&request, &mut remaining) };
    let error = unsafe { *__errno() };
    set_errno(saved_errno);
    if result == 0 {
        0
    } else if error == EINTR {
        // Returning a truncated fraction would incorrectly claim completion.
        (remaining.tv_sec as u32)
            .saturating_add(u32::from(remaining.tv_nsec != 0))
            .min(seconds)
    } else {
        seconds
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn usleep(microseconds: u64) -> c_int {
    // The SDK's useconds_t is unsigned long (64 bits), not a Linux u32.
    let request = Timespec {
        tv_sec: (microseconds / 1_000_000) as i64,
        tv_nsec: ((microseconds % 1_000_000) * 1_000) as i64,
    };
    unsafe { nanosleep(&request, ptr::null_mut()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn nanosleep(request: *const Timespec, remaining: *mut Timespec) -> c_int {
    pthread_testcancel();
    if request.is_null() {
        return sleep_failure(EFAULT);
    }
    let request = match time_memory::read_timespec(request) {
        Ok(request) => request,
        Err(error) => {
            return sleep_failure(error);
        }
    };
    if request.tv_sec < 0 || !(0..1_000_000_000).contains(&request.tv_nsec) {
        return sleep_failure(EINVAL);
    }
    let duration = match (request.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(request.tv_nsec as u64))
    {
        Some(duration) => duration,
        None => {
            return sleep_failure(EINVAL);
        }
    };
    if duration != 0 {
        let (_, control) = match register_current_thread() {
            Some(current) => current,
            None => {
                return sleep_failure(EAGAIN);
            }
        };
        let generation = control.caught_signal_generation.load(Ordering::Acquire);
        let deadline = match monotonic_nanoseconds()
            .and_then(|now| now.checked_add(duration).ok_or(EOVERFLOW))
        {
            Ok(deadline) => deadline,
            Err(error) => {
                return sleep_failure(error);
            }
        };
        loop {
            use mochios_posix_client::time::{SleepObservation, observe_sleep};
            let wake = control.wait_generation.load(Ordering::Acquire);
            pthread_testcancel();
            let now = match monotonic_nanoseconds() {
                Ok(now) => now,
                Err(error) => {
                    return sleep_failure(error);
                }
            };
            match observe_sleep(
                deadline,
                now,
                generation,
                control.caught_signal_generation.load(Ordering::Acquire),
            ) {
                SleepObservation::Complete => break,
                SleepObservation::Interrupted {
                    remaining_nanoseconds,
                } => {
                    if !remaining.is_null() {
                        if let Err(error) = time_memory::write_timespec(
                            remaining,
                            Timespec {
                                tv_sec: (remaining_nanoseconds / 1_000_000_000) as i64,
                                tv_nsec: (remaining_nanoseconds % 1_000_000_000) as i64,
                            },
                        ) {
                            return sleep_failure(error);
                        }
                    }
                    return sleep_failure(EINTR);
                }
                SleepObservation::Waiting => {}
            }
            if let Err(error) = mochios_posix_client::synchronization::wait_u32(
                &control.wait_generation,
                wake,
                deadline,
            ) {
                return sleep_failure(map_kernel_errno(error.raw()));
            }
        }
    }
    pthread_testcancel();
    if !remaining.is_null() {
        if let Err(error) = time_memory::write_timespec(
            remaining,
            Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
        ) {
            return sleep_failure(error);
        }
    }
    pthread_testcancel();
    0
}

fn sleep_failure(error: c_int) -> c_int {
    // Native failures and checked user-copy failures can also deliver an
    // upcall. Finish the cancellation point before returning their errno.
    pthread_testcancel();
    set_errno(error);
    -1
}

#[unsafe(no_mangle)]
pub extern "C" fn _unlink(path: *const c_char) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = (|| {
        unlink_posix_at(-2, path, 0)?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn unlink(path: *const c_char) -> c_int {
    _unlink(path)
}

fn unlink_posix_at(dirfd: c_int, path: *const c_char, flags: c_int) -> Result<(), c_int> {
    const AT_REMOVEDIR: c_int = 0x0008;
    if flags & !AT_REMOVEDIR != 0 {
        return Err(EINVAL);
    }
    let mut options = 0;
    if flags & AT_REMOVEDIR != 0 {
        options |= posix_protocol::UNLINK_REMOVE_DIRECTORY;
    }
    path_io::unlink(dirfd, path, options)
}

#[unsafe(no_mangle)]
pub extern "C" fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(unlink_posix_at(dirfd, path, flags).map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn _link(old_path: *const c_char, new_path: *const c_char) -> c_int {
    if old_path.is_null() || new_path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(link_posix_at(-2, old_path, -2, new_path, 0).map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn link(old_path: *const c_char, new_path: *const c_char) -> c_int {
    _link(old_path, new_path)
}

fn link_posix_at(
    old_dirfd: c_int,
    old_path: *const c_char,
    new_dirfd: c_int,
    new_path: *const c_char,
    flags: c_int,
) -> Result<(), c_int> {
    path_io::link(old_dirfd, old_path, new_dirfd, new_path, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn linkat(
    old_dirfd: c_int,
    old_path: *const c_char,
    new_dirfd: c_int,
    new_path: *const c_char,
    flags: c_int,
) -> c_int {
    if old_path.is_null() || new_path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(
        link_posix_at(old_dirfd, old_path, new_dirfd, new_path, flags).map(|_| 0),
        -1,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn _symlink(target: *const c_char, link_path: *const c_char) -> c_int {
    if target.is_null() || link_path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = symlink_posix_at(target, -2, link_path).map(|_| 0);
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn symlink(target: *const c_char, link_path: *const c_char) -> c_int {
    _symlink(target, link_path)
}

fn symlink_posix_at(
    target: *const c_char,
    dirfd: c_int,
    link_path: *const c_char,
) -> Result<(), c_int> {
    path_io::symlink(target, dirfd, link_path)
}

#[unsafe(no_mangle)]
pub extern "C" fn symlinkat(
    target: *const c_char,
    dirfd: c_int,
    link_path: *const c_char,
) -> c_int {
    if target.is_null() || link_path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(symlink_posix_at(target, dirfd, link_path).map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn _readlink(path: *const c_char, output: *mut c_char, size: usize) -> isize {
    if path.is_null() || output.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    if size == 0 {
        set_errno(EINVAL);
        return -1;
    }
    let result = readlink_posix_at(-2, path, output, size);
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn readlink(path: *const c_char, output: *mut c_char, size: usize) -> isize {
    _readlink(path, output, size)
}

fn readlink_posix_at(
    dirfd: c_int,
    path: *const c_char,
    output: *mut c_char,
    size: usize,
) -> Result<isize, c_int> {
    path_io::readlink(dirfd, path, output, size)
}

#[unsafe(no_mangle)]
pub extern "C" fn readlinkat(
    dirfd: c_int,
    path: *const c_char,
    output: *mut c_char,
    size: usize,
) -> isize {
    if path.is_null() || output.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    if size == 0 {
        set_errno(EINVAL);
        return -1;
    }
    result_with_errno(readlink_posix_at(dirfd, path, output, size), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn _mkdir(path: *const c_char, mode: c_int) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = path_io::mkdir(-2, path, mode as u32).map(|_| 0);
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn mkdir(path: *const c_char, mode: c_int) -> c_int {
    _mkdir(path, mode)
}

#[unsafe(no_mangle)]
pub extern "C" fn mkdirat(dirfd: c_int, path: *const c_char, mode: c_int) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = path_io::mkdir(dirfd, path, mode as u32).map(|_| 0);
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn _rmdir(path: *const c_char) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = unlink_posix_at(-2, path, 0x0008).map(|_| 0);
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn rmdir(path: *const c_char) -> c_int {
    _rmdir(path)
}

#[unsafe(no_mangle)]
pub extern "C" fn _rename(old_path: *const c_char, new_path: *const c_char) -> c_int {
    if old_path.is_null() || new_path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = rename_posix_at(-2, old_path, -2, new_path).map(|_| 0);
    result_with_errno(result, -1)
}

fn rename_posix_base(
    dirfd: c_int,
    path: impl AsRef<[u8]>,
) -> Result<(StatAtBase<u32>, Option<fd_lease::Lease>), c_int> {
    if path.as_ref().first() == Some(&b'/') {
        return Ok((StatAtBase::ProcessRoot, None));
    }
    if dirfd == -2 || i64::from(dirfd) == AT_FDCWD {
        return Ok((StatAtBase::ProcessCwd, None));
    }
    let entry = with_fd_entry(dirfd)?;
    if entry.handle.kind != FdKind::ObjectDirectory {
        return Err(ENOTDIR);
    }
    let base = StatAtBase::Directory(ObjectHandleAttachment {
        handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
        rights: entry.rights,
    });
    Ok((base, Some(entry)))
}

fn rename_posix_at(
    old_dirfd: c_int,
    old_path: *const c_char,
    new_dirfd: c_int,
    new_path: *const c_char,
) -> Result<(), c_int> {
    path_io::rename(old_dirfd, old_path, new_dirfd, new_path)
}

#[unsafe(no_mangle)]
pub extern "C" fn renameat(
    old_dirfd: c_int,
    old_path: *const c_char,
    new_dirfd: c_int,
    new_path: *const c_char,
) -> c_int {
    if old_path.is_null() || new_path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(
        rename_posix_at(old_dirfd, old_path, new_dirfd, new_path).map(|_| 0),
        -1,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn chdir(path: *const c_char) -> c_int {
    if path.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    let result = change_directory_path(path).map(|_| 0);
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn fchdir(fd: c_int) -> c_int {
    result_with_errno(path_io::fchdir(fd).map(|_| 0), -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn getcwd(buffer: *mut c_char, size: usize) -> *mut c_char {
    result_with_errno(current_directory::copy(buffer, size), ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn realpath(path: *const c_char, resolved_path: *mut c_char) -> *mut c_char {
    result_with_errno(canonical_path::resolve(path, resolved_path), ptr::null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_memalign(memptr: *mut *mut c_void, alignment: usize, size: usize) -> c_int {
    if memptr.is_null() {
        return EINVAL;
    }
    if !alignment.is_power_of_two() || alignment < core::mem::size_of::<*mut c_void>() {
        return EINVAL;
    }
    let ptr_value = unsafe { memalign(alignment, size) };
    if ptr_value.is_null() {
        return ENOMEM;
    }
    unsafe {
        *memptr = ptr_value;
    }
    0
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
    let result = execve_with_launch_context(path, argv, envp);
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
pub extern "C" fn execv(path: *const c_char, argv: *const *const c_char) -> c_int {
    _execve(path, argv, unsafe { environ as *const *const c_char })
}

#[unsafe(no_mangle)]
pub extern "C" fn _waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int {
    let result = (|| {
        if options & !(WNOHANG | WUNTRACED | WCONTINUED) != 0 {
            return Err(EINVAL);
        }
        let (_, control) = register_current_thread().ok_or(EAGAIN)?;
        let caught = control.nonrestart_signal_generation.load(Ordering::Acquire);
        let client = posix_client().map_err(map_posix_client_error)?;
        let waited = if options & WNOHANG != 0 {
            client
                .wait_child(pid as i64, options as u32)
                .map_err(map_posix_client_error)?
        } else {
            loop {
                if control.nonrestart_signal_generation.load(Ordering::Acquire) != caught {
                    return Err(EINTR);
                }
                let epoch = client
                    .thread_signal_epoch()
                    .map_err(map_posix_client_error)?;
                if control.nonrestart_signal_generation.load(Ordering::Acquire) != caught {
                    return Err(EINTR);
                }
                match client.wait_child_since(pid as i64, options as u32, epoch) {
                    Ok(waited) => break waited,
                    Err(PosixClientError::Remote(posix_protocol::STATUS_EINTR)) => {
                        // The server did not consume any child event. Dispatch
                        // before choosing EINTR, restart, or default stop/resume.
                        drain_pending_signals()?;
                    }
                    Err(error) => return Err(map_posix_client_error(error)),
                }
            }
        };
        wait_output::publish(waited.process_id, waited.status, status)
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int {
    _waitpid(pid, status, options)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_create(
    thread: *mut Pthread,
    attr: *const PthreadAttr,
    start: Option<PthreadStart>,
    argument: *mut c_void,
) -> c_int {
    if thread.is_null() || start.is_none() {
        return EINVAL;
    }
    reap_detached_threads();
    let inherited_signal_mask = match register_current_thread() {
        Some((_, control)) => match has_posix_environment() {
            Ok(true) => match service_signal_mask(control, posix_protocol::SIGNAL_MASK_QUERY, 0) {
                Ok(mask) => mask,
                Err(error) => return error,
            },
            Ok(false) => control.signal_mask.load(Ordering::Acquire),
            Err(error) => return error,
        },
        None => return EAGAIN,
    };

    let (stack_address, stack_size, guard_size, owns_stack, detachstate) = if attr.is_null() {
        (
            ptr::null_mut(),
            PTHREAD_DEFAULT_STACK_SIZE,
            PAGE_SIZE,
            true,
            PTHREAD_CREATE_JOINABLE,
        )
    } else {
        let attr = unsafe { &*attr };
        if attr.is_initialized == 0
            || !matches!(
                attr.detachstate,
                PTHREAD_CREATE_DETACHED | PTHREAD_CREATE_JOINABLE
            )
        {
            return EINVAL;
        }
        let size = attr.stacksize;
        if size < PTHREAD_STACK_MIN {
            return EINVAL;
        }
        (
            attr.stackaddr,
            size,
            attr.guardsize,
            attr.stackaddr.is_null(),
            attr.detachstate,
        )
    };
    // Owned mappings include the inaccessible guard prefix. Track the whole
    // reservation so every failure, join, detach and fork cleanup releases it.
    let (stack_base, stack_size) = if owns_stack {
        match thread_stack::allocate(stack_size, guard_size) {
            Ok(mapping) => mapping,
            Err(ENOMEM) => return EAGAIN,
            Err(error) => return error,
        }
    } else {
        (stack_address as usize, stack_size)
    };
    let Some((token, control, _preparation)) = reserve_thread_control() else {
        if owns_stack {
            let _ = syscall::raw_syscall2(
                syscall::SyscallNumber::MemoryUnmap,
                stack_base as u64,
                stack_size as u64,
            );
        }
        return EAGAIN;
    };
    control.start.store(
        start.map(|function| function as usize).unwrap_or(0),
        Ordering::Relaxed,
    );
    control.argument.store(argument as usize, Ordering::Relaxed);
    control.stack_base.store(stack_base, Ordering::Relaxed);
    control.stack_size.store(stack_size, Ordering::Relaxed);
    control
        .owns_stack
        .store(u32::from(owns_stack), Ordering::Relaxed);
    control
        .signal_mask
        .store(inherited_signal_mask, Ordering::Relaxed);
    if let Err(error) = allocate_thread_reent(control) {
        control.state.store(THREAD_REAPING, Ordering::Relaxed);
        release_thread_control(control);
        return if error == ENOMEM { EAGAIN } else { error };
    }
    // Admission must finish in the creating thread. A child cannot report an
    // AS-limit failure by killing the whole process after pthread_create won.
    if let Err(error) = allocate_signal_stack(control) {
        control.state.store(THREAD_REAPING, Ordering::Relaxed);
        release_thread_control(control);
        return if error == ENOMEM { EAGAIN } else { error };
    }
    control.joinability.store(
        if detachstate == PTHREAD_CREATE_DETACHED {
            THREAD_DETACHED
        } else {
            THREAD_JOINABLE
        },
        Ordering::Relaxed,
    );

    let stack_end = match stack_base.checked_add(stack_size) {
        Some(end) => end,
        None => {
            control.state.store(THREAD_REAPING, Ordering::Relaxed);
            release_thread_control(control);
            return EINVAL;
        }
    };
    let stack_pointer = (stack_end & !0xf).saturating_sub(8);
    let context = syscall::ThreadCreateContext {
        entry: pthread_start_trampoline as *const () as u64,
        stack_pointer: stack_pointer as u64,
        argument: control as *const ThreadControl as u64,
        thread_local_base: 0,
        flags: 0,
        reserved: [0; 3],
        registers: syscall::ThreadInitialRegisters::default(),
    };
    let native_id = match syscall_errno(syscall::raw_syscall2(
        syscall::SyscallNumber::ThreadCreate,
        (&context as *const syscall::ThreadCreateContext) as u64,
        core::mem::size_of::<syscall::ThreadCreateContext>() as u64,
    )) {
        Ok(native_id) => native_id,
        Err(error) => {
            control.state.store(THREAD_REAPING, Ordering::Relaxed);
            release_thread_control(control);
            return if error == ENOMEM { EAGAIN } else { error };
        }
    };
    let _ = control
        .native_id
        .compare_exchange(0, native_id, Ordering::Release, Ordering::Relaxed);
    unsafe { thread.write(token) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_join(thread: Pthread, value: *mut *mut c_void) -> c_int {
    pthread_testcancel();
    let Some(control) = thread_control(thread) else {
        return ESRCH;
    };
    let Some((current, waiter)) = register_current_thread() else {
        return EAGAIN;
    };
    if current == thread {
        return EDEADLK;
    }
    if control
        .joinability
        .compare_exchange(
            THREAD_JOINABLE,
            THREAD_JOIN_CLAIMED,
            Ordering::AcqRel,
            Ordering::Relaxed,
        )
        .is_err()
    {
        return EINVAL;
    }
    // The join claim permits exactly one waiter. Publish its generation-tagged
    // process-local token before inspecting target state, never an IPC pointer.
    control.join_waiter.store(current, Ordering::Release);
    loop {
        let wake = waiter.wait_generation.load(Ordering::Acquire);
        join_cancel_point(control);
        let state = control.state.load(Ordering::Acquire);
        if state == THREAD_EXITED {
            match native_thread_retired(control) {
                Ok(true) => {
                    join_cancel_point(control);
                    break;
                }
                Ok(false) => {
                    let _ = syscall::raw_syscall0(syscall::SyscallNumber::ThreadYield);
                    continue;
                }
                Err(error) => {
                    release_join_claim(control);
                    return error;
                }
            }
        }
        if !matches!(state, THREAD_STARTING | THREAD_RUNNING) {
            release_join_claim(control);
            return ESRCH;
        }
        if let Err(error) = mochios_posix_client::synchronization::wait_u32(
            &waiter.wait_generation,
            wake,
            syscall::ADDRESS_WAIT_INFINITE,
        ) {
            release_join_claim(control);
            return map_kernel_errno(error.raw());
        }
    }
    if !value.is_null() {
        unsafe { value.write(control.result.load(Ordering::Acquire) as *mut c_void) };
    }
    if control
        .state
        .compare_exchange(
            THREAD_EXITED,
            THREAD_REAPING,
            Ordering::AcqRel,
            Ordering::Relaxed,
        )
        .is_err()
    {
        release_join_claim(control);
        return ESRCH;
    }
    release_thread_control(control);
    0
}

fn release_join_claim(control: &ThreadControl) {
    control.join_waiter.store(0, Ordering::Release);
    control.joinability.store(THREAD_JOINABLE, Ordering::Release);
}

fn join_cancel_point(target: &ThreadControl) {
    let Some((_, caller)) = current_thread_control() else {
        return;
    };
    if caller.cancel_state.load(Ordering::Acquire) == PTHREAD_CANCEL_ENABLE
        && caller.cancel_pending.load(Ordering::Acquire) != 0
    {
        // ThreadExit does not unwind Rust guards. Undo the internal join claim
        // explicitly before running application cleanup (which may join again).
        release_join_claim(target);
        finish_thread(caller, usize::MAX as *mut c_void);
    }
}

fn notify_join_waiter(target: &ThreadControl) {
    let token = target.join_waiter.load(Ordering::Acquire);
    if let Some(waiter) = thread_control(token) {
        notify_thread_waiter(waiter);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_detach(thread: Pthread) -> c_int {
    let Some(control) = thread_control(thread) else {
        return ESRCH;
    };
    if control
        .joinability
        .compare_exchange(
            THREAD_JOINABLE,
            THREAD_DETACHED,
            Ordering::AcqRel,
            Ordering::Relaxed,
        )
        .is_err()
    {
        return EINVAL;
    }
    reap_detached_threads();
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_exit(value: *mut c_void) -> ! {
    let (_, control) = register_current_thread().unwrap_or_else(|| process_exit(127));
    finish_thread(control, value)
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_self() -> Pthread {
    register_current_thread()
        .map(|(thread, _)| thread)
        .unwrap_or(0)
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_equal(left: Pthread, right: Pthread) -> c_int {
    c_int::from(left == right)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_key_create(
    key: *mut PthreadKey,
    destructor: Option<PthreadKeyDestructor>,
) -> c_int {
    if key.is_null() {
        return EINVAL;
    }
    // A sibling must not snapshot INITIALIZING or a half-published callback.
    // The mutation also defers delivery through the checked MemoryCopy below.
    let _mutation = thread_lifecycle::mutate();
    for (slot, control) in THREAD_KEYS.iter().enumerate() {
        if control
            .allocated
            .compare_exchange(
                THREAD_KEY_FREE,
                THREAD_KEY_INITIALIZING,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            continue;
        }
        let generation = mochios_posix_client::thread::next_generation(
            control.generation.load(Ordering::Relaxed),
        );
        control.destructor.store(
            destructor.map_or(0, |function| function as usize),
            Ordering::Relaxed,
        );
        control.generation.store(generation, Ordering::Release);
        let Some(token) = mochios_posix_client::thread::ThreadKeyToken::new(slot, generation)
        else {
            control.destructor.store(0, Ordering::Relaxed);
            control.allocated.store(THREAD_KEY_FREE, Ordering::Release);
            return EAGAIN;
        };
        // Keep the reserved slot private until the caller receives its token.
        // A faultable output must not leak a key or invoke a destructor.
        if let Err(error) = user_copy::write(key.cast(), &token.raw().to_ne_bytes()) {
            control.destructor.store(0, Ordering::Relaxed);
            control.allocated.store(THREAD_KEY_FREE, Ordering::Release);
            return error;
        }
        control
            .allocated
            .store(THREAD_KEY_ALLOCATED, Ordering::Release);
        return 0;
    }
    EAGAIN
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_key_delete(key: PthreadKey) -> c_int {
    let _mutation = thread_lifecycle::mutate();
    let Some((_, control)) = thread_key_control(key) else {
        return EINVAL;
    };
    if control
        .allocated
        .compare_exchange(
            THREAD_KEY_ALLOCATED,
            THREAD_KEY_INITIALIZING,
            Ordering::AcqRel,
            Ordering::Relaxed,
        )
        .is_err()
    {
        return EINVAL;
    }
    // Keep the slot unavailable until the old callback is cleared. Publishing
    // FREE first lets a concurrent creator install a destructor that this
    // deletion would then overwrite.
    control.destructor.store(0, Ordering::Release);
    control.allocated.store(THREAD_KEY_FREE, Ordering::Release);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_setspecific(key: PthreadKey, value: *const c_void) -> c_int {
    let Some((token, _)) = thread_key_control(key) else {
        return EINVAL;
    };
    let (_, thread) = match register_current_thread() {
        Some(current) => current,
        None => return EAGAIN,
    };
    thread.specific_values[token.slot()].store(value as usize, Ordering::Relaxed);
    thread.specific_generations[token.slot()].store(token.generation(), Ordering::Release);
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_getspecific(key: PthreadKey) -> *mut c_void {
    let Some((token, _)) = thread_key_control(key) else {
        return ptr::null_mut();
    };
    let Some((_, thread)) = current_thread_control() else {
        return ptr::null_mut();
    };
    if thread.specific_generations[token.slot()].load(Ordering::Acquire) != token.generation() {
        return ptr::null_mut();
    }
    thread.specific_values[token.slot()].load(Ordering::Acquire) as *mut c_void
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _pthread_cleanup_push(
    context: *mut thread_cleanup::Context,
    routine: Option<thread_cleanup::Routine>,
    argument: *mut c_void,
) {
    if context.is_null() {
        process_exit(127);
    }
    let (_, control) = register_current_thread().unwrap_or_else(|| process_exit(127));
    let cancel_type = control.cancel_type.load(Ordering::Acquire) as c_int;
    unsafe { thread_cleanup::push(&control.cleanup_head, context, routine, argument, cancel_type) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _pthread_cleanup_pop(context: *mut thread_cleanup::Context, execute: c_int) {
    let (_, control) = register_current_thread().unwrap_or_else(|| process_exit(127));
    let _ = unsafe { thread_cleanup::pop(&control.cleanup_head, context, execute != 0) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _pthread_cleanup_push_defer(
    context: *mut thread_cleanup::Context,
    routine: Option<thread_cleanup::Routine>,
    argument: *mut c_void,
) {
    // Asynchronous cancellation is not yet supported, so the saved type is
    // currently deferred. Preserve it using the SDK context for future support.
    unsafe { _pthread_cleanup_push(context, routine, argument) };
    let (_, control) = register_current_thread().unwrap_or_else(|| process_exit(127));
    control.cancel_type.store(PTHREAD_CANCEL_DEFERRED, Ordering::Release);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _pthread_cleanup_pop_restore(context: *mut thread_cleanup::Context, execute: c_int) {
    let (_, control) = register_current_thread().unwrap_or_else(|| process_exit(127));
    if let Some(previous) = unsafe { thread_cleanup::pop(&control.cleanup_head, context, execute != 0) } {
        control.cancel_type.store(previous as u32, Ordering::Release);
    }
}

fn update_cancel_control(
    control: &ThreadControl,
    field: &AtomicU32,
    value: u32,
    previous: *mut c_int,
) -> c_int {
    // A native upcall must not reenter between snapshot, faultable copy and
    // commit. Application pointers never become Rust references, including
    // when this API itself is called from an already active upcall.
    let Some(_delivery) =
        mochios_posix_client::upcall_guard::Guard::enter(&control.native_delivery_defer)
    else {
        return EOVERFLOW;
    };
    let old = field.load(Ordering::Acquire);
    if !previous.is_null() {
        if let Err(error) = user_copy::write(previous.cast(), &(old as c_int).to_ne_bytes()) {
            return error;
        }
    }
    field.store(value, Ordering::Release);
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_setcancelstate(state: c_int, old_state: *mut c_int) -> c_int {
    if !matches!(state as u32, PTHREAD_CANCEL_ENABLE | PTHREAD_CANCEL_DISABLE) {
        return EINVAL;
    }
    let (_, control) = match register_current_thread() {
        Some(current) => current,
        None => return EAGAIN,
    };
    // Only deferred cancellation is currently supported. Re-enabling it is
    // not a cancellation point: retain the request until an explicit point.
    update_cancel_control(control, &control.cancel_state, state as u32, old_state)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_setcanceltype(cancel_type: c_int, old_type: *mut c_int) -> c_int {
    if cancel_type as u32 == PTHREAD_CANCEL_ASYNCHRONOUS {
        return ENOSYS;
    }
    if cancel_type as u32 != PTHREAD_CANCEL_DEFERRED {
        return EINVAL;
    }
    let (_, control) = match register_current_thread() {
        Some(current) => current,
        None => return EAGAIN,
    };
    update_cancel_control(control, &control.cancel_type, PTHREAD_CANCEL_DEFERRED, old_type)
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_cancel(thread: Pthread) -> c_int {
    let Some(control) = thread_control(thread) else {
        return ESRCH;
    };
    control.cancel_pending.store(1, Ordering::Release);
    notify_thread_waiter(control);
    native_mutex_wake_all(&control.state);
    0
}

fn notify_thread_waiter(control: &ThreadControl) {
    control.multiplex_generation.fetch_add(1, Ordering::Release);
    native_counter_wake_all(&control.multiplex_generation);
    control.wait_generation.fetch_add(1, Ordering::Release);
    native_mutex_wake_all(&control.wait_generation);
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_testcancel() {
    let Some((_, control)) = current_thread_control() else {
        return;
    };
    if control.cancel_state.load(Ordering::Acquire) == PTHREAD_CANCEL_ENABLE
        && control.cancel_pending.load(Ordering::Acquire) != 0
    {
        finish_thread(control, usize::MAX as *mut c_void);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_init(attr: *mut PthreadAttr) -> c_int {
    if attr.is_null() {
        return EINVAL;
    }
    unsafe {
        attr.write(PthreadAttr {
            is_initialized: 1,
            stackaddr: ptr::null_mut(),
            stacksize: PTHREAD_DEFAULT_STACK_SIZE,
            guardsize: PAGE_SIZE,
            reserved: [0; 2],
            detachstate: PTHREAD_CREATE_JOINABLE,
        })
    };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_destroy(attr: *mut PthreadAttr) -> c_int {
    if attr.is_null() || unsafe { (*attr).is_initialized } == 0 {
        return EINVAL;
    }
    unsafe { (*attr).is_initialized = 0 };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setstacksize(
    attr: *mut PthreadAttr,
    stack_size: usize,
) -> c_int {
    if attr.is_null()
        || unsafe { (*attr).is_initialized } == 0
        || stack_size < PTHREAD_STACK_MIN
    {
        return EINVAL;
    }
    unsafe { (*attr).stacksize = stack_size };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getstacksize(
    attr: *const PthreadAttr,
    stack_size: *mut usize,
) -> c_int {
    if attr.is_null() || stack_size.is_null() || unsafe { (*attr).is_initialized } == 0 {
        return EINVAL;
    }
    unsafe { stack_size.write((*attr).stacksize) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setstack(
    attr: *mut PthreadAttr,
    stack_address: *mut c_void,
    stack_size: usize,
) -> c_int {
    if attr.is_null()
        || stack_address.is_null()
        || unsafe { (*attr).is_initialized } == 0
        || stack_size < PTHREAD_STACK_MIN
    {
        return EINVAL;
    }
    unsafe {
        (*attr).stackaddr = stack_address;
        (*attr).stacksize = stack_size;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getstack(
    attr: *const PthreadAttr,
    stack_address: *mut *mut c_void,
    stack_size: *mut usize,
) -> c_int {
    if attr.is_null()
        || stack_address.is_null()
        || stack_size.is_null()
        || unsafe { (*attr).is_initialized } == 0
    {
        return EINVAL;
    }
    unsafe {
        stack_address.write((*attr).stackaddr);
        stack_size.write((*attr).stacksize);
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setdetachstate(
    attr: *mut PthreadAttr,
    detachstate: c_int,
) -> c_int {
    if attr.is_null()
        || unsafe { (*attr).is_initialized } == 0
        || !matches!(
            detachstate,
            PTHREAD_CREATE_DETACHED | PTHREAD_CREATE_JOINABLE
        )
    {
        return EINVAL;
    }
    unsafe { (*attr).detachstate = detachstate };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getdetachstate(
    attr: *const PthreadAttr,
    detachstate: *mut c_int,
) -> c_int {
    if attr.is_null() || detachstate.is_null() || unsafe { (*attr).is_initialized } == 0 {
        return EINVAL;
    }
    unsafe { detachstate.write((*attr).detachstate) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setguardsize(
    attr: *mut PthreadAttr,
    guard_size: usize,
) -> c_int {
    if attr.is_null() || unsafe { (*attr).is_initialized } == 0 {
        return EINVAL;
    }
    // Preserve the requested size. Only allocation rounds to a whole page;
    // pthread_attr_getguardsize returns exactly the caller's value.
    unsafe { (*attr).guardsize = guard_size };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getguardsize(
    attr: *const PthreadAttr,
    guard_size: *mut usize,
) -> c_int {
    if attr.is_null() || guard_size.is_null() || unsafe { (*attr).is_initialized } == 0 {
        return EINVAL;
    }
    unsafe { guard_size.write((*attr).guardsize) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnattr_init(attr: *mut *mut PosixSpawnAttr) -> c_int {
    if attr.is_null() {
        return EINVAL;
    }
    let _delivery = defer_native_delivery();
    let value = unsafe { malloc(core::mem::size_of::<PosixSpawnAttr>()) }.cast::<PosixSpawnAttr>();
    if value.is_null() {
        return ENOMEM;
    }
    unsafe {
        value.write(PosixSpawnAttr::new());
    }
    if let Err(error) = user_copy::write(attr.cast(), &(value as usize).to_ne_bytes()) {
        unsafe { free(value.cast()) };
        return error;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnattr_destroy(attr: *mut *mut PosixSpawnAttr) -> c_int {
    let _delivery = defer_native_delivery();
    let value = match spawn_attributes::handle_address(attr.cast()) {
        Ok(value) => value,
        Err(error) => return error,
    };
    // A failed copy must not leave a caller-visible reference to freed storage.
    if let Err(error) = user_copy::write(attr.cast(), &0usize.to_ne_bytes()) {
        return error;
    }
    unsafe { free(value as *mut c_void) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnattr_getflags(
    attr: *const *mut PosixSpawnAttr,
    flags: *mut i16,
) -> c_int {
    spawn_attributes::get::<{ core::mem::size_of::<i16>() }>(
        attr,
        flags.cast(),
        core::mem::offset_of!(PosixSpawnAttr, sa_flags),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnattr_setflags(attr: *mut *mut PosixSpawnAttr, flags: i16) -> c_int {
    if matches!(
        mochios_posix_client::spawn::classify_attribute_flags(flags),
        mochios_posix_client::spawn::AttributeFlags::Invalid
    ) {
        return EINVAL;
    }
    spawn_attributes::set::<{ core::mem::size_of::<i16>() }>(
        attr.cast_const(),
        ptr::addr_of!(flags).cast(),
        core::mem::offset_of!(PosixSpawnAttr, sa_flags),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnattr_getpgroup(
    attr: *const *mut PosixSpawnAttr,
    pgroup: *mut c_int,
) -> c_int {
    spawn_attributes::get::<{ core::mem::size_of::<c_int>() }>(
        attr,
        pgroup.cast(),
        core::mem::offset_of!(PosixSpawnAttr, sa_pgroup),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnattr_setpgroup(
    attr: *mut *mut PosixSpawnAttr,
    pgroup: c_int,
) -> c_int {
    spawn_attributes::set::<{ core::mem::size_of::<c_int>() }>(
        attr.cast_const(),
        ptr::addr_of!(pgroup).cast(),
        core::mem::offset_of!(PosixSpawnAttr, sa_pgroup),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnattr_getschedparam(
    attr: *const *mut PosixSpawnAttr,
    schedparam: *mut SchedParam,
) -> c_int {
    spawn_attributes::get::<{ core::mem::size_of::<c_int>() }>(
        attr,
        schedparam.cast(),
        core::mem::offset_of!(PosixSpawnAttr, sa_schedparam)
            + core::mem::offset_of!(SchedParam, sched_priority),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnattr_setschedparam(
    attr: *mut *mut PosixSpawnAttr,
    schedparam: *const SchedParam,
) -> c_int {
    spawn_attributes::set::<{ core::mem::size_of::<c_int>() }>(
        attr.cast_const(),
        schedparam.cast(),
        core::mem::offset_of!(PosixSpawnAttr, sa_schedparam)
            + core::mem::offset_of!(SchedParam, sched_priority),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnattr_getschedpolicy(
    attr: *const *mut PosixSpawnAttr,
    policy: *mut c_int,
) -> c_int {
    spawn_attributes::get::<{ core::mem::size_of::<c_int>() }>(
        attr,
        policy.cast(),
        core::mem::offset_of!(PosixSpawnAttr, sa_schedpolicy),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnattr_setschedpolicy(
    attr: *mut *mut PosixSpawnAttr,
    policy: c_int,
) -> c_int {
    spawn_attributes::set::<{ core::mem::size_of::<c_int>() }>(
        attr.cast_const(),
        ptr::addr_of!(policy).cast(),
        core::mem::offset_of!(PosixSpawnAttr, sa_schedpolicy),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnattr_getsigdefault(
    attr: *const *mut PosixSpawnAttr,
    sigdefault: *mut u64,
) -> c_int {
    spawn_attributes::get::<{ core::mem::size_of::<u64>() }>(
        attr,
        sigdefault.cast(),
        core::mem::offset_of!(PosixSpawnAttr, sa_sigdefault),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnattr_setsigdefault(
    attr: *mut *mut PosixSpawnAttr,
    sigdefault: *const u64,
) -> c_int {
    spawn_attributes::set::<{ core::mem::size_of::<u64>() }>(
        attr.cast_const(),
        sigdefault.cast(),
        core::mem::offset_of!(PosixSpawnAttr, sa_sigdefault),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnattr_getsigmask(
    attr: *const *mut PosixSpawnAttr,
    sigmask: *mut u64,
) -> c_int {
    spawn_attributes::get::<{ core::mem::size_of::<u64>() }>(
        attr,
        sigmask.cast(),
        core::mem::offset_of!(PosixSpawnAttr, sa_sigmask),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnattr_setsigmask(
    attr: *mut *mut PosixSpawnAttr,
    sigmask: *const u64,
) -> c_int {
    spawn_attributes::set::<{ core::mem::size_of::<u64>() }>(
        attr.cast_const(),
        sigmask.cast(),
        core::mem::offset_of!(PosixSpawnAttr, sa_sigmask),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawn_file_actions_init(actions: *mut *mut PosixSpawnFileActions) -> c_int {
    if actions.is_null() {
        return EINVAL;
    }
    let _delivery = defer_native_delivery();
    match unsafe { allocate_file_actions_object() } {
        Ok(value) => {
            if let Err(error) = user_copy::write(actions.cast(), &(value as usize).to_ne_bytes()) {
                unsafe { release_file_actions_object(value) };
                return error;
            }
            0
        }
        Err(errno_value) => errno_value,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawn_file_actions_destroy(
    actions: *mut *mut PosixSpawnFileActions,
) -> c_int {
    let _delivery = defer_native_delivery();
    if actions.is_null() {
        return EINVAL;
    }
    let actions_ptr = match file_actions_object(actions) {
        Ok(value) => value,
        Err(error) => return error,
    };
    // Do not free a list while the caller-visible handle still refers to it.
    if let Err(error) = user_copy::write(actions.cast(), &0usize.to_ne_bytes()) {
        return error;
    }
    // Safety: actions_ptr is the queue object previously allocated by init().
    let mut current = unsafe { (*actions_ptr).fa_list.stqh_first };
    while !current.is_null() {
        // Safety: current walks the action queue owned by actions_ptr.
        let next = unsafe { (*current).fae_list.stqe_next };
        // Safety: the active union field is selected by fae_action and these
        // strings were allocated by the corresponding add operation.
        unsafe {
            match (*current).fae_action {
                FAE_OPEN => free((*current).fae_data.open.path.cast()),
                FAE_CHDIR => free((*current).fae_data.dir.cast()),
                _ => {}
            }
        }
        unsafe { release_file_action_entry(current) };
        current = next;
    }
    unsafe {
        release_file_actions_object(actions_ptr);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawn_file_actions_addopen(
    actions: *mut *mut PosixSpawnFileActions,
    fildes: c_int,
    path: *const c_char,
    oflag: c_int,
    mode: u32,
) -> c_int {
    if actions.is_null() || path.is_null() {
        return EINVAL;
    }
    if fildes < 0 {
        return EBADF;
    }
    let _delivery = defer_native_delivery();
    let actions_ptr = match file_actions_object(actions) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let path = match spawn_file_actions::Path::capture(path as usize) {
        Ok(value) => value.into_raw(),
        Err(errno_value) => return errno_value,
    };
    let entry = match unsafe { allocate_file_action_entry() } {
        Ok(value) => value,
        Err(errno_value) => {
            unsafe { free(path.cast()) };
            return errno_value;
        }
    };
    unsafe {
        (*entry).fae_action = FAE_OPEN;
        (*entry).fae_fildes = fildes;
        (*entry).fae_data.open = PosixSpawnFileActionOpen { path, oflag, mode };
        append_file_action(actions_ptr, entry);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawn_file_actions_addclose(
    actions: *mut *mut PosixSpawnFileActions,
    fildes: c_int,
) -> c_int {
    let _delivery = defer_native_delivery();
    if actions.is_null() {
        return EINVAL;
    }
    if fildes < 0 {
        return EBADF;
    }
    let actions_ptr = match file_actions_object(actions) {
        Ok(value) => value,
        Err(error) => return error,
    };
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
    let _delivery = defer_native_delivery();
    if actions.is_null() {
        return EINVAL;
    }
    if fildes < 0 || newfildes < 0 {
        return EBADF;
    }
    let actions_ptr = match file_actions_object(actions) {
        Ok(value) => value,
        Err(error) => return error,
    };
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
pub extern "C" fn posix_spawn_file_actions_addchdir_np(
    actions: *mut *mut PosixSpawnFileActions,
    path: *const c_char,
) -> c_int {
    if actions.is_null() || path.is_null() {
        return EINVAL;
    }
    let _delivery = defer_native_delivery();
    let actions_ptr = match file_actions_object(actions) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let path = match spawn_file_actions::Path::capture(path as usize) {
        Ok(value) => value.into_raw(),
        Err(errno_value) => return errno_value,
    };
    let entry = match unsafe { allocate_file_action_entry() } {
        Ok(value) => value,
        Err(errno_value) => {
            unsafe { free(path.cast()) };
            return errno_value;
        }
    };
    unsafe {
        (*entry).fae_action = FAE_CHDIR;
        (*entry).fae_data.dir = path;
        append_file_action(actions_ptr, entry);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawn_file_actions_addchdir(
    actions: *mut *mut PosixSpawnFileActions,
    path: *const c_char,
) -> c_int {
    posix_spawn_file_actions_addchdir_np(actions, path)
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawn_file_actions_addfchdir_np(
    actions: *mut *mut PosixSpawnFileActions,
    fildes: c_int,
) -> c_int {
    let _delivery = defer_native_delivery();
    if actions.is_null() {
        return EINVAL;
    }
    if fildes < 0 {
        return EBADF;
    }
    let actions_ptr = match file_actions_object(actions) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let entry = match unsafe { allocate_file_action_entry() } {
        Ok(value) => value,
        Err(errno_value) => return errno_value,
    };
    unsafe {
        (*entry).fae_action = FAE_FCHDIR;
        (*entry).fae_data.dirfd = fildes;
        append_file_action(actions_ptr, entry);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawn_file_actions_addfchdir(
    actions: *mut *mut PosixSpawnFileActions,
    fildes: c_int,
) -> c_int {
    posix_spawn_file_actions_addfchdir_np(actions, fildes)
}

#[unsafe(no_mangle)]
pub extern "C" fn _posix_spawn(
    pid: *mut c_int,
    path: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if pid.is_null() || path.is_null() {
        return EINVAL;
    }
    let attributes = match spawn_attributes::read_optional(attrp) {
        Ok(attributes) => attributes,
        Err(errno_value) => return errno_value,
    };
    spawn_file_actions::with(file_actions, |actions| {
        spawn_with_actions(pid, path, actions, attributes, argv, envp)
    })
}

fn spawn_with_actions(
    pid: *mut c_int,
    path: *const c_char,
    actions: &spawn_file_actions::Actions,
    attributes: Option<PosixSpawnAttr>,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    spawn_resources::with(|resources| {
        spawn_with_resources(pid, path, actions, attributes, argv, envp, resources)
    })
}

fn spawn_with_resources(
    pid: *mut c_int,
    path: *const c_char,
    actions: &spawn_file_actions::Actions,
    attributes: Option<PosixSpawnAttr>,
    argv: *const *const c_char,
    envp: *const *const c_char,
    resources: &mut spawn_resources::Resources,
) -> c_int {
    let snapshot = SpawnSnapshot {
        path,
        argv,
        envp,
    };

    let (child_pid, desired_fds, _process_handle) = match resources.clone_registered() {
        Ok(value) => value,
        Err(errno_value) => return errno_value,
    };

    if child_pid == 0 {
        resources
            .child_writer()
            .unwrap_or_else(|error| process_exit(error));
        // This child's normal FD table is authoritative for file actions and
        // any signal-handler reentry. The snapshot holds the same inherited
        // references; it is metadata, not a second native Handle owner.
        state().fds = desired_fds;
        if let Err(errno_value) = apply_spawn_attributes(attributes) {
            resources.fail(errno_value);
        }
        if let Err(errno_value) = apply_spawn_file_actions(actions) {
            resources.fail(errno_value);
        }
        if let Err(errno_value) =
            execve_with_launch_context(snapshot.path, snapshot.argv, snapshot.envp)
        {
            resources.fail(errno_value);
        }
        resources.fail(EIO);
    }

    match resources.wait() {
        Ok(mochios_posix_client::spawn::ExecStatus::Succeeded) => {
            resources.publish(child_pid, pid)
        }
        Ok(mochios_posix_client::spawn::ExecStatus::Failed(errno_value)) | Err(errno_value) => errno_value,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawn(
    pid: *mut c_int,
    path: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    _posix_spawn(pid, path, file_actions, attrp, argv, envp)
}

#[unsafe(no_mangle)]
pub extern "C" fn posix_spawnp(
    pid: *mut c_int,
    file: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    exec_search::_posix_spawnp(pid, file, file_actions, attrp, argv, envp)
}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_init(lock: *mut *mut LockOpaque) {
    if lock.is_null() {
        return;
    }
    let allocation = unsafe { malloc(core::mem::size_of::<LockOpaque>()) }.cast::<LockOpaque>();
    if allocation.is_null() {
        process_exit(127);
    }
    unsafe { allocation.write(LockOpaque::new(true)) };
    unsafe { lock.write(allocation) };
}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_init_recursive(lock: *mut *mut LockOpaque) {
    __retarget_lock_init(lock);
}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_acquire(lock: *mut LockOpaque) {
    let Some(lock) = (unsafe { lock.as_ref() }) else {
        process_exit(127);
    };
    libc_lock::acquire(lock);
}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_acquire_recursive(lock: *mut LockOpaque) {
    let Some(lock_ref) = (unsafe { lock.as_ref() }) else {
        process_exit(127);
    };
    let thread_id = newlib_lock_identity();
    if lock_ref.owner.load(Ordering::Acquire) == thread_id {
        if lock_ref.depth.fetch_add(1, Ordering::Relaxed) == u32::MAX {
            process_exit(127);
        }
        return;
    }
    __retarget_lock_acquire(lock);
    lock_ref.depth.store(1, Ordering::Relaxed);
    lock_ref.owner.store(thread_id, Ordering::Release);
}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_try_acquire(lock: *mut LockOpaque) -> c_int {
    let Some(lock) = (unsafe { lock.as_ref() }) else {
        return 0;
    };
    c_int::from(libc_lock::try_acquire(lock))
}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_try_acquire_recursive(lock: *mut LockOpaque) -> c_int {
    let Some(lock_ref) = (unsafe { lock.as_ref() }) else {
        return 0;
    };
    let thread_id = newlib_lock_identity();
    if lock_ref.owner.load(Ordering::Acquire) == thread_id {
        if lock_ref.depth.fetch_add(1, Ordering::Relaxed) == u32::MAX {
            process_exit(127);
        }
        return 1;
    }
    if __retarget_lock_try_acquire(lock) == 0 {
        return 0;
    }
    lock_ref.depth.store(1, Ordering::Relaxed);
    lock_ref.owner.store(thread_id, Ordering::Release);
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_release(lock: *mut LockOpaque) {
    let Some(lock) = (unsafe { lock.as_ref() }) else {
        process_exit(127);
    };
    libc_lock::release(lock);
}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_release_recursive(lock: *mut LockOpaque) {
    let Some(lock_ref) = (unsafe { lock.as_ref() }) else {
        process_exit(127);
    };
    let thread_id = newlib_lock_identity();
    if lock_ref.owner.load(Ordering::Acquire) != thread_id {
        process_exit(127);
    }
    let depth = lock_ref.depth.load(Ordering::Relaxed);
    if depth == 0 {
        process_exit(127);
    }
    if depth > 1 {
        lock_ref.depth.store(depth - 1, Ordering::Relaxed);
        return;
    }
    __retarget_lock_release(lock);
}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_close(lock: *mut LockOpaque) {
    let Some(lock_ref) = (unsafe { lock.as_ref() }) else {
        return;
    };
    if !lock_ref.dynamic {
        return;
    }
    if lock_ref.state.load(Ordering::Acquire) != 0 {
        process_exit(127);
    }
    unsafe { free(lock.cast()) };
}

#[unsafe(no_mangle)]
pub extern "C" fn __retarget_lock_close_recursive(lock: *mut LockOpaque) {
    __retarget_lock_close(lock);
}
