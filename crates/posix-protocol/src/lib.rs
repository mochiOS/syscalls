#![no_std]

//! Versioned wire protocol shared by the mochiOS POSIX client and service.
//!
//! The protocol contains no process-local pointers or file-descriptor numbers.
//! Kernel objects travel as IPC handle attachments, outside the byte payload.

pub const MAGIC: [u8; 4] = *b"POSX";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 32;
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;
pub mod named_semaphore;
pub mod shared_memory;
pub mod socket;
pub mod socket_record;
pub mod socket_route;
pub mod socket_transfer;
pub mod fault_signal;
pub mod signal_origin;
pub mod signal_wait;

/// Opaque LaunchContext key under which the POSIX control endpoint is passed.
///
/// This value belongs to the POSIX user-space contract. mnu treats it as an
/// uninterpreted integer.
pub const CONTROL_HANDLE_KEY: u64 = u64::from_le_bytes(*b"POSXCTRL");
/// Explicit ProcessHandle selected by the userspace launcher for bootstrap.
/// mnu only transfers the opaque key and attenuated object reference.
pub const BOOTSTRAP_PROCESS_HANDLE_KEY: u64 = u64::from_le_bytes(*b"POSXINIT");

const FD_HANDLE_KEY_PREFIX: u64 = 0x504f_5348_0000_0000;
const FD_METADATA_KEY_PREFIX: u64 = 0x504f_5346_0000_0000;
const FD_KEY_INDEX_MASK: u64 = u32::MAX as u64;
const FD_METADATA_TAG: u16 = 0x5046;

pub const INHERITED_FD_KIND_STDIN: u8 = 1;
pub const INHERITED_FD_KIND_STDOUT: u8 = 2;
pub const INHERITED_FD_KIND_STDERR: u8 = 3;
pub const INHERITED_FD_KIND_FILE: u8 = 5;
pub const INHERITED_FD_KIND_DIRECTORY: u8 = 6;
pub const INHERITED_FD_KIND_STREAM_READ: u8 = 7;
pub const INHERITED_FD_KIND_STREAM_WRITE: u8 = 8;
pub const INHERITED_FD_KIND_PTY: u8 = 9;
pub const INHERITED_FD_KIND_SHARED_MEMORY: u8 = 10;
pub const INHERITED_FD_KIND_SOCKET: u8 = 11;
pub const INHERITED_FD_KIND_DATAGRAM: u8 = 12;
pub const INHERITED_FD_DESCRIPTOR_CLOEXEC: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InheritedFdMetadata {
    pub kind: u8,
    pub open_flags: u32,
    pub descriptor_flags: u8,
}

pub const fn fd_handle_key(fd: i32) -> Option<u64> {
    if fd < 0 {
        return None;
    }
    Some(FD_HANDLE_KEY_PREFIX | fd as u32 as u64)
}

pub const fn fd_metadata_key(fd: i32) -> Option<u64> {
    if fd < 0 {
        return None;
    }
    Some(FD_METADATA_KEY_PREFIX | fd as u32 as u64)
}

const fn valid_inherited_fd_kind(kind: u8) -> bool {
    matches!(
        kind,
        INHERITED_FD_KIND_STDIN
            | INHERITED_FD_KIND_STDOUT
            | INHERITED_FD_KIND_STDERR
            | INHERITED_FD_KIND_FILE
            | INHERITED_FD_KIND_DIRECTORY
            | INHERITED_FD_KIND_STREAM_READ
            | INHERITED_FD_KIND_STREAM_WRITE
            | INHERITED_FD_KIND_PTY
            | INHERITED_FD_KIND_SHARED_MEMORY
            | INHERITED_FD_KIND_SOCKET
            | INHERITED_FD_KIND_DATAGRAM
    )
}

pub const fn inherited_fd_kind_requires_handle(kind: u8) -> Option<bool> {
    if !valid_inherited_fd_kind(kind) {
        return None;
    }
    Some(matches!(
        kind,
        INHERITED_FD_KIND_FILE
            | INHERITED_FD_KIND_DIRECTORY
            | INHERITED_FD_KIND_STREAM_READ
            | INHERITED_FD_KIND_STREAM_WRITE
            | INHERITED_FD_KIND_PTY
            | INHERITED_FD_KIND_SHARED_MEMORY
            | INHERITED_FD_KIND_SOCKET
            | INHERITED_FD_KIND_DATAGRAM
    ))
}

pub const fn encode_inherited_fd_metadata(metadata: InheritedFdMetadata) -> Option<u64> {
    if !valid_inherited_fd_kind(metadata.kind)
        || metadata.descriptor_flags & !INHERITED_FD_DESCRIPTOR_CLOEXEC != 0
    {
        return None;
    }
    Some(
        metadata.open_flags as u64
            | ((metadata.descriptor_flags as u64) << 32)
            | ((metadata.kind as u64) << 40)
            | ((FD_METADATA_TAG as u64) << 48),
    )
}

pub const fn decode_inherited_fd_metadata(value: u64) -> Option<InheritedFdMetadata> {
    if (value >> 48) as u16 != FD_METADATA_TAG {
        return None;
    }
    let metadata = InheritedFdMetadata {
        kind: (value >> 40) as u8,
        open_flags: value as u32,
        descriptor_flags: (value >> 32) as u8,
    };
    if !valid_inherited_fd_kind(metadata.kind)
        || metadata.descriptor_flags & !INHERITED_FD_DESCRIPTOR_CLOEXEC != 0
    {
        return None;
    }
    Some(metadata)
}

pub const fn inherited_fd_from_key(key: u64) -> Option<i32> {
    let prefix = key & !FD_KEY_INDEX_MASK;
    if prefix != FD_HANDLE_KEY_PREFIX && prefix != FD_METADATA_KEY_PREFIX {
        return None;
    }
    let index = (key & FD_KEY_INDEX_MASK) as u32;
    if index > i32::MAX as u32 {
        return None;
    }
    Some(index as i32)
}

pub const OP_PING: u16 = 1;
pub const OP_SESSION_REGISTER: u16 = 2;
pub const OP_SESSION_INFO: u16 = 3;
pub const OP_UMASK_SET: u16 = 4;
pub const OP_OPEN_AT: u16 = 5;
pub const OP_STAT_AT: u16 = 6;
pub const OP_FSTAT: u16 = 7;
pub const OP_ACCESS_AT: u16 = 8;
pub const OP_CHDIR_AT: u16 = 9;
pub const OP_FCHDIR: u16 = 10;
pub const OP_GETCWD: u16 = 11;
pub const OP_SET_UID: u16 = 12;
pub const OP_SET_GID: u16 = 13;
pub const OP_FTRUNCATE: u16 = 14;
pub const OP_FSYNC: u16 = 15;
pub const OP_FGETFL: u16 = 16;
pub const OP_FSETFL: u16 = 17;
pub const OP_MKDIR_AT: u16 = 18;
pub const OP_UNLINK_AT: u16 = 19;
pub const OP_RENAME_AT: u16 = 20;
pub const OP_TRUNCATE_AT: u16 = 21;
pub const OP_SYMLINK_AT: u16 = 22;
pub const OP_READLINK_AT: u16 = 23;
pub const OP_CHMOD_AT: u16 = 24;
pub const OP_CHOWN_AT: u16 = 25;
pub const OP_FCHMOD: u16 = 26;
pub const OP_FCHOWN: u16 = 27;
pub const OP_PROCESS_FORKED: u16 = 28;
pub const OP_WAIT_CHILD: u16 = 29;
pub const OP_PROCESS_INFO: u16 = 30;
pub const OP_SET_PROCESS_GROUP: u16 = 31;
pub const OP_CREATE_SESSION: u16 = 32;
pub const OP_RESOURCE_LIMIT: u16 = 33;
pub const OP_SIGNAL_SEND: u16 = 34;
pub const OP_SIGNAL_PENDING: u16 = 35;
pub const OP_SIGNAL_THREAD_REGISTER: u16 = 37;
pub const OP_GROUPS_GET: u16 = 38;
pub const OP_GROUPS_SET: u16 = 39;
pub const OP_LINK_AT: u16 = 40;
pub const OP_CHROOT_AT: u16 = 41;
pub const OP_SET_EFFECTIVE_UID: u16 = 42;
pub const OP_SET_EFFECTIVE_GID: u16 = 43;
pub const OP_RESET_EFFECTIVE_IDS: u16 = 44;
pub const OP_PTY_OPEN: u16 = 45;
pub const OP_TERMINAL_ACQUIRE: u16 = 46;
pub const OP_TERMINAL_RELEASE: u16 = 47;
pub const OP_TERMINAL_GET_FOREGROUND: u16 = 48;
pub const OP_TERMINAL_SET_FOREGROUND: u16 = 49;
pub const OP_PROCESS_STOPPED: u16 = 50;
pub const OP_SIGNAL_DELIVERY_COMPLETE: u16 = 51;
pub const OP_PROCESS_SIGNALED: u16 = 52;
pub const OP_SIGNAL_CHILD_OPTIONS: u16 = 53;
pub const OP_PROCESS_SPAWNED: u16 = 54;
pub const OP_PROCESS_SESSION_INFO: u16 = 55;
/// Empty payload, followed by requester WAIT and child WAIT|SIGNAL objects.
pub const OP_PROCESS_LAUNCHED: u16 = 56;
/// Abort an unpublished broker launch using one explicit WAIT-only child Handle.
pub const OP_PROCESS_LAUNCH_ABORT: u16 = 57;
pub const OP_SET_REAL_EFFECTIVE_UID: u16 = 58;
pub const OP_SET_REAL_EFFECTIVE_GID: u16 = 59;
/// Initialize an already running boot process through an attached ProcessHandle.
pub const OP_PROCESS_INITIALIZE: u16 = 60;
/// Empty payload and one WAIT|SIGNAL ProcessHandle for a launcher's tree root.
/// Only its recorded launcher may terminate the tree. Retain its userspace
/// records until a separate reclaim request, including after successful exit.
pub const OP_PROCESS_TREE_TERMINATE: u16 = 61;
/// Empty payload and the same WAIT|SIGNAL root; reclaim only a confirmed exited
/// tree. ESRCH means no root environment remains, not proof of a prior exit.
pub const OP_PROCESS_TREE_RECLAIM: u16 = 62;
/// Signal metadata only; handler addresses remain process-local.
pub const OP_SIGNAL_DISPOSITION: u16 = 63;
/// Called by the installed image, never before a potentially failing exec.
/// Empty payload; returns the SIG_IGN bitset retained across image replacement.
pub const OP_SIGNAL_IMAGE_STARTED: u16 = 64;
/// The thread is identified by authenticated IPC metadata, not request bytes.
pub const OP_SIGNAL_THREAD_MASK: u16 = 65;
/// Empty payload; delivery uses the authenticated thread's service-owned mask.
pub const OP_SIGNAL_THREAD_DEQUEUE: u16 = 66;
/// Empty payload; returns pending signals blocked by the authenticated thread.
pub const OP_SIGNAL_THREAD_PENDING: u16 = 67;
/// SignalSendRequest with selector zero; the target is the authenticated caller
/// thread, never a client-provided PID or TID.
pub const OP_SIGNAL_THREAD_RAISE: u16 = 68;
/// Empty payload; returns the authenticated thread's signal-delivery sequence.
pub const OP_SIGNAL_THREAD_EPOCH: u16 = 69;
/// WaitRequest followed by a u64 delivery epoch. Caller identity is supplied
/// by authenticated endpoint metadata, not the request payload.
pub const OP_WAIT_CHILD_GUARDED: u16 = 70;
/// SignalSendRequest with selector zero and one WAIT|SIGNAL ThreadHandle.
/// Sender and target identities are obtained from native metadata only.
pub const OP_SIGNAL_THREAD_SEND: u16 = 71;
/// Empty request. Returns CPU counts of children waited for by the caller;
/// caller identity comes only from authenticated transport metadata.
pub const OP_WAITED_CHILD_CPU_USAGE: u16 = 73;
pub const OP_SEMAPHORE_OPEN: u16 = 74;
pub const OP_SEMAPHORE_UNLINK: u16 = 75;
pub const OP_SHARED_MEMORY_OPEN: u16 = 76;
pub const OP_SHARED_MEMORY_UNLINK: u16 = 77;
pub const OP_SHARED_MEMORY_BACKING: u16 = 78;
pub const OP_SOCKET_CREATE: u16 = 79;
pub const OP_SOCKET_PAIR: u16 = 80;
/// Accept one queued connection from exactly one attached listener Handle.
/// Request carries socket::Accept; success carries peer Address and one new
/// socket Handle. Empty queue returns EAGAIN; waiting remains client-side.
pub const OP_SOCKET_ACCEPT: u16 = 81;
/// Address payload and exactly one attached socket Handle. Blocking behavior
/// comes from the shared socket description, not a caller-supplied flag.
/// Success returns socket::ConnectReply; Waiting also attaches one job Handle.
pub const OP_SOCKET_CONNECT: u16 = 82;
/// SignalSendRequest with selector zero; synchronous BUS/SEGV delivery to
/// the authenticated calling thread, without consuming pending signals.
pub const OP_SIGNAL_THREAD_FAULT: u16 = 83;
/// SignalDelivery request; reads provenance only for a delivery owned by the
/// authenticated calling thread. Does not consume the completion token.
/// Returns signal_origin::Origin including the retained child event/status.
pub const OP_SIGNAL_DELIVERY_ORIGIN: u16 = 85;
/// SignalWaitRequest; atomically accepts one blocked signal and its provenance
/// for the authenticated thread. Returns signal_wait::Accepted. EAGAIN stays
/// internal to deferred service processing. The old number-only opcode is gone.
pub const OP_SIGNAL_THREAD_WAIT_INFO: u16 = 86;
/// signal_wait timed request: mask, epoch and finite absolute monotonic ns.
/// Success returns signal_wait::Accepted; expiry returns EAGAIN.
pub const OP_SIGNAL_THREAD_TIMED_WAIT: u16 = 87;
/// Exactly one READ|TRANSFER socket Handle and an unsigned u64 minimum queue
/// length. Empty success payload and one WAIT|TRANSFER notification Handle.
/// Registration is atomic with the queue check; final Handle release cancels.
pub const OP_SOCKET_RECEIVE_WAIT: u16 = 88;
/// Empty request, no attachments. Returns one SEND|TRANSFER socket-worker
/// endpoint. It permits transport only: every record request must separately
/// attach a socket with the required data rights and a RAM buffer.
pub const OP_SOCKET_RECORD_ENDPOINT: u16 = 89;
/// Atomically updates selected mutable flags of one explicitly attached OFD.
/// Requires CONTROL|TRANSFER. FILE_FLAGS_UPDATE_PAYLOAD_LEN input; empty reply.
pub const OP_FUPDATEFL: u16 = 90;
pub const WAITED_CHILD_CPU_USAGE_LEN: usize = 40;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitedChildCpuUsage {
    pub user_ticks: u128,
    pub kernel_ticks: u128,
    pub ticks_per_second: u64,
}

pub fn encode_waited_child_cpu_usage(
    usage: WaitedChildCpuUsage,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() < WAITED_CHILD_CPU_USAGE_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if usage.ticks_per_second == 0 && (usage.user_ticks != 0 || usage.kernel_ticks != 0) {
        return Err(ProtocolError::InvalidLength);
    }
    output[..16].copy_from_slice(&usage.user_ticks.to_le_bytes());
    output[16..32].copy_from_slice(&usage.kernel_ticks.to_le_bytes());
    put_u64(output, 32, usage.ticks_per_second);
    Ok(())
}

pub fn decode_waited_child_cpu_usage(input: &[u8]) -> Result<WaitedChildCpuUsage, ProtocolError> {
    if input.len() != WAITED_CHILD_CPU_USAGE_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let usage = WaitedChildCpuUsage {
        user_ticks: u128::from_le_bytes(input[..16].try_into().unwrap()),
        kernel_ticks: u128::from_le_bytes(input[16..32].try_into().unwrap()),
        ticks_per_second: get_u64(input, 32),
    };
    if usage.ticks_per_second == 0 && (usage.user_ticks != 0 || usage.kernel_ticks != 0) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(usage)
}
pub const SIGNAL_WAIT_REQUEST_LEN: usize = 16;
pub const WAIT_GUARDED_REQUEST_LEN: usize = 24;
pub const SIGNAL_THREAD_MASK_LEN: usize = 16;
pub const SIGNAL_MASK_QUERY: u32 = 0;
pub const SIGNAL_MASK_SET: u32 = 1;
pub const SIGNAL_MASK_BLOCK: u32 = 2;
pub const SIGNAL_MASK_UNBLOCK: u32 = 3;
/// Seeds a new thread once, but preserves an existing mask across image entry.
pub const SIGNAL_MASK_INITIALIZE: u32 = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignalMaskRequest {
    pub operation: u32,
    pub mask: u64,
}
pub const SIGNAL_DISPOSITION_SET: u32 = 1;
pub const SIGNAL_DISPOSITION_LEN: usize = 16;
pub const SIGNAL_DISPOSITION_DEFAULT: u32 = 0;
pub const SIGNAL_DISPOSITION_IGNORE: u32 = 1;
pub const SIGNAL_DISPOSITION_CAUGHT: u32 = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignalDisposition {
    pub signal: u32,
    pub kind: u32,
    pub child_options: u32,
}
pub const OP_STATUS: u16 = 0x8000;

pub const STATUS_OK: i32 = 0;
pub const STATUS_EPERM: i32 = -1;
pub const STATUS_ENOENT: i32 = -2;
pub const STATUS_ESRCH: i32 = -3;
pub const STATUS_EINTR: i32 = -4;
pub const STATUS_EIO: i32 = -5;
pub const STATUS_ECHILD: i32 = -10;
pub const STATUS_EAGAIN: i32 = -11;
pub const STATUS_ENOTTY: i32 = -25;
pub const STATUS_ENOSYS: i32 = -38;

pub const SESSION_INFO_LEN: usize = 20;
pub const UMASK_PAYLOAD_LEN: usize = 4;
pub const CREDENTIAL_ID_PAYLOAD_LEN: usize = 4;
pub const CREDENTIAL_PAIR_PAYLOAD_LEN: usize = 8;
/// Leave this ID unchanged in a real/effective credential update.
pub const CREDENTIAL_ID_UNCHANGED: u32 = u32::MAX;
pub const FILE_LENGTH_PAYLOAD_LEN: usize = 8;
pub const FILE_FLAGS_PAYLOAD_LEN: usize = 4;
pub const FILE_FLAGS_UPDATE_PAYLOAD_LEN: usize = 8;
pub const FILE_OWNER_PAYLOAD_LEN: usize = 8;
pub const OPEN_AT_HEADER_LEN: usize = 16;
pub const STAT_AT_HEADER_LEN: usize = 12;
pub const ACCESS_AT_HEADER_LEN: usize = 16;
pub const RENAME_AT_HEADER_LEN: usize = 16;
pub const LINK_AT_HEADER_LEN: usize = 16;
pub const TRUNCATE_AT_HEADER_LEN: usize = 16;
pub const SYMLINK_AT_HEADER_LEN: usize = 16;
pub const CHOWN_AT_HEADER_LEN: usize = 20;
pub const FILE_STATUS_LEN: usize = 112;
pub const WAIT_REQUEST_LEN: usize = 16;
pub const WAIT_RESULT_LEN: usize = 16;
pub const PROCESS_ID_REQUEST_LEN: usize = 8;
pub const PROCESS_GROUP_REQUEST_LEN: usize = 16;
pub const PROCESS_INFO_LEN: usize = 32;
pub const RESOURCE_LIMIT_REQUEST_LEN: usize = 32;
pub const RESOURCE_LIMIT_LEN: usize = 16;
pub const SIGNAL_SEND_REQUEST_LEN: usize = 16;
pub const SIGNAL_MASK_LEN: usize = 8;
pub const SIGNAL_DELIVERY_LEN: usize = 16;
pub const SIGNAL_CHILD_OPTIONS_LEN: usize = 4;
pub const TERMINAL_CONTROL_CHARACTERS: usize = 32;
pub const TERMINAL_ATTRIBUTES_LEN: usize = 56;
pub const TERMINAL_FLUSH_LEN: usize = 4;
pub const MAX_SUPPLEMENTARY_GROUPS: usize = 32;
pub const GROUP_LIST_HEADER_LEN: usize = 4;
pub const GROUP_LIST_MAX_LEN: usize =
    GROUP_LIST_HEADER_LEN + MAX_SUPPLEMENTARY_GROUPS * core::mem::size_of::<u32>();
pub const MAX_PATH_LEN: usize = 4096;
pub const MAX_CONTROL_PAYLOAD_LEN: usize = RENAME_AT_HEADER_LEN + MAX_PATH_LEN * 2;
pub const CONTROL_MESSAGE_LEN: usize = HEADER_LEN + MAX_CONTROL_PAYLOAD_LEN;

pub const STAT_NOFOLLOW: u32 = 1 << 0;
pub const STAT_FLAGS_ALL: u32 = STAT_NOFOLLOW;
pub const CHOWN_NOFOLLOW: u32 = 1 << 0;
pub const CHOWN_FLAGS_ALL: u32 = CHOWN_NOFOLLOW;
pub const LINK_FOLLOW_SOURCE: u32 = 1 << 0;
pub const LINK_FLAGS_ALL: u32 = LINK_FOLLOW_SOURCE;

pub const ACCESS_READ: u32 = 1 << 2;
pub const ACCESS_WRITE: u32 = 1 << 1;
pub const ACCESS_EXECUTE: u32 = 1 << 0;
pub const ACCESS_MODES_ALL: u32 = ACCESS_READ | ACCESS_WRITE | ACCESS_EXECUTE;
pub const ACCESS_EFFECTIVE_IDS: u32 = 1 << 0;
pub const ACCESS_NOFOLLOW: u32 = 1 << 1;
pub const ACCESS_FLAGS_ALL: u32 = ACCESS_EFFECTIVE_IDS | ACCESS_NOFOLLOW;

pub const OPEN_READ: u32 = 1 << 0;
pub const OPEN_WRITE: u32 = 1 << 1;
pub const OPEN_CREATE: u32 = 1 << 2;
pub const OPEN_EXCLUSIVE: u32 = 1 << 3;
pub const OPEN_TRUNCATE: u32 = 1 << 4;
pub const OPEN_APPEND: u32 = 1 << 5;
pub const OPEN_NONBLOCK: u32 = 1 << 6;
pub const OPEN_DIRECTORY: u32 = 1 << 7;
pub const OPEN_NOFOLLOW: u32 = 1 << 8;
pub const OPEN_OPTIONS_ALL: u32 = OPEN_READ
    | OPEN_WRITE
    | OPEN_CREATE
    | OPEN_EXCLUSIVE
    | OPEN_TRUNCATE
    | OPEN_APPEND
    | OPEN_NONBLOCK
    | OPEN_DIRECTORY
    | OPEN_NOFOLLOW;

pub const MUTABLE_STATUS_FLAGS: u32 = OPEN_APPEND | OPEN_NONBLOCK;

pub const UNLINK_REMOVE_DIRECTORY: u32 = 1 << 0;
pub const UNLINK_FLAGS_ALL: u32 = UNLINK_REMOVE_DIRECTORY;

pub const WAIT_NOHANG: u32 = 1 << 0;
pub const WAIT_UNTRACED: u32 = 1 << 1;
pub const WAIT_CONTINUED: u32 = 1 << 3;
pub const WAIT_OPTIONS_ALL: u32 = WAIT_NOHANG | WAIT_UNTRACED | WAIT_CONTINUED;
pub const WAIT_STATUS_CONTINUED: u32 = 0xffff;

pub const RESOURCE_LIMIT_SET: u32 = 1 << 0;
pub const RESOURCE_LIMIT_FLAGS_ALL: u32 = RESOURCE_LIMIT_SET;
pub const RLIM_INFINITY: u64 = u64::MAX;

pub const RLIMIT_CPU: u32 = 0;
pub const RLIMIT_FSIZE: u32 = 1;
pub const RLIMIT_DATA: u32 = 2;
pub const RLIMIT_STACK: u32 = 3;
pub const RLIMIT_CORE: u32 = 4;
pub const RLIMIT_RSS: u32 = 5;
pub const RLIMIT_NPROC: u32 = 6;
pub const RLIMIT_NOFILE: u32 = 7;
pub const RLIMIT_MEMLOCK: u32 = 8;
pub const RLIMIT_AS: u32 = 9;
pub const RLIMIT_COUNT: u32 = 10;

pub const SIGNAL_MAX: u32 = 64;
pub const SIGNAL_CHILD_OPTION_NOCLDSTOP: u32 = 1 << 0;
pub const SIGNAL_CHILD_OPTION_NOCLDWAIT: u32 = 1 << 1;
pub const SIGNAL_CHILD_OPTIONS_ALL: u32 = SIGNAL_CHILD_OPTION_NOCLDSTOP | SIGNAL_CHILD_OPTION_NOCLDWAIT;
pub const SIGNAL_HUP: u32 = 1;
pub const SIGNAL_INT: u32 = 2;
pub const SIGNAL_QUIT: u32 = 3;
pub const SIGNAL_KILL: u32 = 9;
pub const SIGNAL_BUS: u32 = 10;
pub const SIGNAL_SEGV: u32 = 11;
pub const SIGNAL_PIPE: u32 = 13;
pub const SIGNAL_URG: u32 = 16;
pub const SIGNAL_STOP: u32 = 17;
pub const SIGNAL_TSTP: u32 = 18;
pub const SIGNAL_CONT: u32 = 19;
pub const SIGNAL_CHLD: u32 = 20;
pub const SIGNAL_TTIN: u32 = 21;
pub const SIGNAL_TTOU: u32 = 22;
pub const SIGNAL_WINCH: u32 = 28;

/// Provider control codes understood by POSIX pseudo-terminal objects.
///
/// These values belong to the user-space POSIX protocol. mnu forwards them as
/// opaque integers and does not interpret terminal semantics.
pub const PTY_CONTROL_GET_ATTRIBUTES: u64 = 0x5054_5900_0000_0001;
pub const PTY_CONTROL_SET_ATTRIBUTES_NOW: u64 = 0x5054_5900_0000_0002;
pub const PTY_CONTROL_SET_ATTRIBUTES_DRAIN: u64 = 0x5054_5900_0000_0003;
pub const PTY_CONTROL_SET_ATTRIBUTES_FLUSH: u64 = 0x5054_5900_0000_0004;
pub const PTY_CONTROL_DRAIN: u64 = 0x5054_5900_0000_0005;
pub const PTY_CONTROL_FLUSH: u64 = 0x5054_5900_0000_0006;
pub const PTY_CONTROL_GET_WINDOW_SIZE: u64 = 0x5054_5900_0000_0007;
pub const PTY_CONTROL_SET_WINDOW_SIZE: u64 = 0x5054_5900_0000_0008;
pub const PTY_CONTROL_FLOW: u64 = 0x5054_5900_0000_0009;
pub const TERMINAL_FLOW_LEN: usize = 4;
pub const TERMINAL_FLOW_OUTPUT_STOP: u32 = 0;
pub const TERMINAL_FLOW_OUTPUT_START: u32 = 1;
pub const TERMINAL_FLOW_INPUT_STOP: u32 = 2;
pub const TERMINAL_FLOW_INPUT_START: u32 = 3;
pub const TERMINAL_WINDOW_SIZE_LEN: usize = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TerminalWindowSize {
    pub rows: u16,
    pub columns: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

pub fn encode_terminal_window_size(
    size: TerminalWindowSize,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() < TERMINAL_WINDOW_SIZE_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    for (index, value) in [size.rows, size.columns, size.pixel_width, size.pixel_height]
        .into_iter()
        .enumerate()
    {
        output[index * 2..index * 2 + 2].copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

pub fn decode_terminal_window_size(input: &[u8]) -> Result<TerminalWindowSize, ProtocolError> {
    if input.len() != TERMINAL_WINDOW_SIZE_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(TerminalWindowSize {
        rows: u16::from_le_bytes([input[0], input[1]]),
        columns: u16::from_le_bytes([input[2], input[3]]),
        pixel_width: u16::from_le_bytes([input[4], input[5]]),
        pixel_height: u16::from_le_bytes([input[6], input[7]]),
    })
}

pub const TERMINAL_FLUSH_INPUT: u32 = 1 << 0;
pub const TERMINAL_FLUSH_OUTPUT: u32 = 1 << 1;
pub const TERMINAL_FLUSH_ALL: u32 = TERMINAL_FLUSH_INPUT | TERMINAL_FLUSH_OUTPUT;

pub const TERMINAL_IFLAG_IGNBRK: u32 = 1 << 0;
pub const TERMINAL_IFLAG_BRKINT: u32 = 1 << 1;
pub const TERMINAL_IFLAG_IGNPAR: u32 = 1 << 2;
pub const TERMINAL_IFLAG_PARMRK: u32 = 1 << 3;
pub const TERMINAL_IFLAG_INPCK: u32 = 1 << 4;
pub const TERMINAL_IFLAG_ISTRIP: u32 = 1 << 5;
pub const TERMINAL_IFLAG_INLCR: u32 = 1 << 6;
pub const TERMINAL_IFLAG_IGNCR: u32 = 1 << 7;
pub const TERMINAL_IFLAG_ICRNL: u32 = 1 << 8;
pub const TERMINAL_IFLAG_IXON: u32 = 1 << 10;
pub const TERMINAL_IFLAG_IXOFF: u32 = 1 << 12;
pub const TERMINAL_IFLAG_IUTF8: u32 = 1 << 14;

pub const TERMINAL_OFLAG_OPOST: u32 = 1 << 0;
pub const TERMINAL_OFLAG_ONLCR: u32 = 1 << 2;

pub const TERMINAL_CFLAG_CS8: u32 = 3 << 4;
pub const TERMINAL_CFLAG_CREAD: u32 = 1 << 7;
pub const TERMINAL_CFLAG_HUPCL: u32 = 1 << 10;
pub const TERMINAL_CFLAG_CLOCAL: u32 = 1 << 11;

pub const TERMINAL_LFLAG_ISIG: u32 = 1 << 0;
pub const TERMINAL_LFLAG_ICANON: u32 = 1 << 1;
pub const TERMINAL_LFLAG_ECHO: u32 = 1 << 3;
pub const TERMINAL_LFLAG_ECHOE: u32 = 1 << 4;
pub const TERMINAL_LFLAG_ECHOK: u32 = 1 << 5;
pub const TERMINAL_LFLAG_ECHONL: u32 = 1 << 6;
pub const TERMINAL_LFLAG_NOFLSH: u32 = 1 << 7;
pub const TERMINAL_LFLAG_TOSTOP: u32 = 1 << 8;
pub const TERMINAL_LFLAG_IEXTEN: u32 = 1 << 15;

pub const TERMINAL_CC_VINTR: usize = 0;
pub const TERMINAL_CC_VQUIT: usize = 1;
pub const TERMINAL_CC_VERASE: usize = 2;
pub const TERMINAL_CC_VKILL: usize = 3;
pub const TERMINAL_CC_VEOF: usize = 4;
pub const TERMINAL_CC_VTIME: usize = 5;
pub const TERMINAL_CC_VMIN: usize = 6;
pub const TERMINAL_CC_VSTART: usize = 8;
pub const TERMINAL_CC_VSTOP: usize = 9;
pub const TERMINAL_CC_VSUSP: usize = 10;
pub const TERMINAL_CC_VEOL: usize = 11;
pub const TERMINAL_CC_VREPRINT: usize = 12;
pub const TERMINAL_CC_VDISCARD: usize = 13;
pub const TERMINAL_CC_VWERASE: usize = 14;
pub const TERMINAL_CC_VLNEXT: usize = 15;
pub const TERMINAL_CC_VEOL2: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalAttributes {
    pub input_flags: u32,
    pub output_flags: u32,
    pub control_flags: u32,
    pub local_flags: u32,
    pub control_characters: [u8; TERMINAL_CONTROL_CHARACTERS],
    pub input_speed: u32,
    pub output_speed: u32,
}

impl TerminalAttributes {
    pub const fn sane() -> Self {
        let mut control_characters = [0; TERMINAL_CONTROL_CHARACTERS];
        control_characters[TERMINAL_CC_VINTR] = 3;
        control_characters[TERMINAL_CC_VQUIT] = 28;
        control_characters[TERMINAL_CC_VERASE] = 127;
        control_characters[TERMINAL_CC_VKILL] = 21;
        control_characters[TERMINAL_CC_VEOF] = 4;
        control_characters[TERMINAL_CC_VMIN] = 1;
        control_characters[TERMINAL_CC_VSTART] = 17;
        control_characters[TERMINAL_CC_VSTOP] = 19;
        control_characters[TERMINAL_CC_VSUSP] = 26;
        control_characters[TERMINAL_CC_VREPRINT] = 18;
        control_characters[TERMINAL_CC_VDISCARD] = 15;
        control_characters[TERMINAL_CC_VWERASE] = 23;
        control_characters[TERMINAL_CC_VLNEXT] = 22;
        Self {
            input_flags: TERMINAL_IFLAG_ICRNL,
            output_flags: TERMINAL_OFLAG_OPOST | TERMINAL_OFLAG_ONLCR,
            control_flags: TERMINAL_CFLAG_CS8 | TERMINAL_CFLAG_CREAD,
            local_flags: TERMINAL_LFLAG_ISIG
                | TERMINAL_LFLAG_ICANON
                | TERMINAL_LFLAG_ECHO
                | TERMINAL_LFLAG_ECHOE
                | TERMINAL_LFLAG_ECHOK,
            control_characters,
            input_speed: 38_400,
            output_speed: 38_400,
        }
    }
}

impl Default for TerminalAttributes {
    fn default() -> Self {
        Self::sane()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignalSendRequest {
    pub selector: i64,
    pub signal: u32,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenBase {
    ProcessRoot = 0,
    ProcessCwd = 1,
    AttachedDirectory = 2,
}

impl OpenBase {
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::ProcessRoot),
            1 => Some(Self::ProcessCwd),
            2 => Some(Self::AttachedDirectory),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenAtRequest<'a> {
    pub base: OpenBase,
    pub options: u32,
    pub mode: u32,
    pub path: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatAtRequest<'a> {
    pub base: OpenBase,
    pub flags: u32,
    pub path: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessAtRequest<'a> {
    pub base: OpenBase,
    pub flags: u32,
    pub modes: u32,
    pub path: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RenameAtRequest<'a> {
    pub old_base: OpenBase,
    pub new_base: OpenBase,
    pub old_path: &'a str,
    pub new_path: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkAtRequest<'a> {
    pub old_base: OpenBase,
    pub new_base: OpenBase,
    pub flags: u32,
    pub old_path: &'a str,
    pub new_path: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TruncateAtRequest<'a> {
    pub base: OpenBase,
    pub length: u64,
    pub path: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymlinkAtRequest<'a> {
    pub base: OpenBase,
    pub target: &'a str,
    pub link_path: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChownAtRequest<'a> {
    pub base: OpenBase,
    pub flags: u32,
    pub uid: u32,
    pub gid: u32,
    pub path: &'a str,
}

/// Architecture-independent representation of the POSIX `struct stat` data.
///
/// This structure is serialized field by field. It is never copied as a Rust
/// structure and therefore does not expose compiler padding or a target ABI.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileStatus {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub link_count: u32,
    pub uid: u32,
    pub gid: u32,
    pub special_device: u64,
    pub size: i64,
    pub block_size: i64,
    pub blocks: i64,
    pub access_time_seconds: i64,
    pub access_time_nanoseconds: i64,
    pub modification_time_seconds: i64,
    pub modification_time_nanoseconds: i64,
    pub change_time_seconds: i64,
    pub change_time_nanoseconds: i64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionInfo {
    pub real_uid: u32,
    pub effective_uid: u32,
    pub real_gid: u32,
    pub effective_gid: u32,
    pub umask: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitRequest {
    pub selector: i64,
    pub options: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitResult {
    pub process_id: u64,
    pub status: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SignalDelivery {
    pub signal: u32,
    pub token: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessInfo {
    pub process_id: u64,
    pub parent_id: u64,
    pub process_group_id: u64,
    pub session_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimit {
    pub soft: u64,
    pub hard: u64,
}

impl ResourceLimit {
    pub const INFINITY: Self = Self {
        soft: RLIM_INFINITY,
        hard: RLIM_INFINITY,
    };
}

impl Default for ResourceLimit {
    fn default() -> Self {
        Self::INFINITY
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceLimitRequest {
    pub process_id: i64,
    pub resource: u32,
    pub flags: u32,
    pub limit: ResourceLimit,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub opcode: u16,
    pub request_id: u64,
    pub flags: u32,
    pub payload_len: u32,
    pub status: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    BufferTooSmall,
    InvalidMagic,
    UnsupportedVersion,
    InvalidLength,
}

pub fn encode(header: Header, payload: &[u8], output: &mut [u8]) -> Result<usize, ProtocolError> {
    if payload.len() != header.payload_len as usize || payload.len() > MAX_MESSAGE_LEN - HEADER_LEN
    {
        return Err(ProtocolError::InvalidLength);
    }
    let total = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }

    output[..HEADER_LEN].fill(0);
    output[0..4].copy_from_slice(&MAGIC);
    put_u16(output, 4, VERSION);
    put_u16(output, 6, header.opcode);
    put_u64(output, 8, header.request_id);
    put_u32(output, 16, header.flags);
    put_u32(output, 20, header.payload_len);
    put_u32(output, 24, header.status as u32);
    output[HEADER_LEN..total].copy_from_slice(payload);
    Ok(total)
}

pub fn decode(input: &[u8]) -> Result<(Header, &[u8]), ProtocolError> {
    if input.len() < HEADER_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if input[0..4] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    if get_u16(input, 4) != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }

    let payload_len = get_u32(input, 20) as usize;
    let total = HEADER_LEN
        .checked_add(payload_len)
        .ok_or(ProtocolError::InvalidLength)?;
    if total > input.len() || total > MAX_MESSAGE_LEN {
        return Err(ProtocolError::InvalidLength);
    }

    Ok((
        Header {
            opcode: get_u16(input, 6),
            request_id: get_u64(input, 8),
            flags: get_u32(input, 16),
            payload_len: payload_len as u32,
            status: get_u32(input, 24) as i32,
        },
        &input[HEADER_LEN..total],
    ))
}

pub fn encode_session_info(info: SessionInfo, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < SESSION_INFO_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, info.real_uid);
    put_u32(output, 4, info.effective_uid);
    put_u32(output, 8, info.real_gid);
    put_u32(output, 12, info.effective_gid);
    put_u32(output, 16, info.umask);
    Ok(())
}

pub fn decode_session_info(input: &[u8]) -> Result<SessionInfo, ProtocolError> {
    if input.len() != SESSION_INFO_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(SessionInfo {
        real_uid: get_u32(input, 0),
        effective_uid: get_u32(input, 4),
        real_gid: get_u32(input, 8),
        effective_gid: get_u32(input, 12),
        umask: get_u32(input, 16),
    })
}

pub fn encode_umask(value: u32, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < UMASK_PAYLOAD_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, value);
    Ok(())
}

pub fn decode_umask(input: &[u8]) -> Result<u32, ProtocolError> {
    if input.len() != UMASK_PAYLOAD_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(get_u32(input, 0))
}

pub fn encode_credential_id(value: u32, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < CREDENTIAL_ID_PAYLOAD_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, value);
    Ok(())
}

/// Fresh-image credentials. Child identity comes only from an attached
/// ProcessHandle; no PID or native credential layout is serialized.
pub fn encode_spawn_credentials(
    uid: u32,
    gid: u32,
    groups: &[u32],
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    if uid == u32::MAX || gid == u32::MAX {
        return Err(ProtocolError::InvalidLength);
    }
    if output.len() < 8 {
        return Err(ProtocolError::BufferTooSmall);
    }
    let length = encode_group_list(groups, &mut output[8..])?;
    put_u32(output, 0, uid);
    put_u32(output, 4, gid);
    Ok(8 + length)
}

pub fn decode_spawn_credentials(
    input: &[u8],
    groups: &mut [u32],
) -> Result<(u32, u32, usize), ProtocolError> {
    if input.len() < 8 {
        return Err(ProtocolError::InvalidLength);
    }
    let uid = get_u32(input, 0);
    let gid = get_u32(input, 4);
    if uid == u32::MAX || gid == u32::MAX {
        return Err(ProtocolError::InvalidLength);
    }
    let count = decode_group_list(&input[8..], groups)?;
    Ok((uid, gid, count))
}

pub fn decode_credential_id(input: &[u8]) -> Result<u32, ProtocolError> {
    if input.len() != CREDENTIAL_ID_PAYLOAD_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(get_u32(input, 0))
}

pub fn encode_credential_pair(
    real: u32,
    effective: u32,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() < CREDENTIAL_PAIR_PAYLOAD_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, real);
    put_u32(output, 4, effective);
    Ok(())
}

pub fn decode_credential_pair(input: &[u8]) -> Result<(u32, u32), ProtocolError> {
    if input.len() != CREDENTIAL_PAIR_PAYLOAD_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok((get_u32(input, 0), get_u32(input, 4)))
}

/// Encodes a supplementary-group list without exposing target ABI layout.
pub fn encode_group_list(groups: &[u32], output: &mut [u8]) -> Result<usize, ProtocolError> {
    if groups.len() > MAX_SUPPLEMENTARY_GROUPS {
        return Err(ProtocolError::InvalidLength);
    }
    let length = GROUP_LIST_HEADER_LEN
        .checked_add(
            groups
                .len()
                .checked_mul(core::mem::size_of::<u32>())
                .ok_or(ProtocolError::InvalidLength)?,
        )
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < length {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, groups.len() as u32);
    for (index, group) in groups.iter().copied().enumerate() {
        put_u32(output, GROUP_LIST_HEADER_LEN + index * 4, group);
    }
    Ok(length)
}

/// Decodes a strictly-sized supplementary-group list into caller storage.
pub fn decode_group_list(input: &[u8], output: &mut [u32]) -> Result<usize, ProtocolError> {
    if input.len() < GROUP_LIST_HEADER_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let count = get_u32(input, 0) as usize;
    if count > MAX_SUPPLEMENTARY_GROUPS {
        return Err(ProtocolError::InvalidLength);
    }
    let expected = GROUP_LIST_HEADER_LEN
        .checked_add(
            count
                .checked_mul(core::mem::size_of::<u32>())
                .ok_or(ProtocolError::InvalidLength)?,
        )
        .ok_or(ProtocolError::InvalidLength)?;
    if input.len() != expected {
        return Err(ProtocolError::InvalidLength);
    }
    if output.len() < count {
        return Err(ProtocolError::BufferTooSmall);
    }
    for (index, group) in output.iter_mut().take(count).enumerate() {
        *group = get_u32(input, GROUP_LIST_HEADER_LEN + index * 4);
    }
    Ok(count)
}

pub fn encode_wait_request(request: WaitRequest, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < WAIT_REQUEST_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..WAIT_REQUEST_LEN].fill(0);
    put_u64(output, 0, request.selector as u64);
    put_u32(output, 8, request.options);
    Ok(())
}

pub fn decode_wait_request(input: &[u8]) -> Result<WaitRequest, ProtocolError> {
    if input.len() != WAIT_REQUEST_LEN || get_u32(input, 12) != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(WaitRequest {
        selector: get_u64(input, 0) as i64,
        options: get_u32(input, 8),
    })
}

pub fn encode_guarded_wait_request(
    request: WaitRequest,
    epoch: u64,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() < WAIT_GUARDED_REQUEST_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    encode_wait_request(request, &mut output[..WAIT_REQUEST_LEN])?;
    put_u64(output, WAIT_REQUEST_LEN, epoch);
    Ok(())
}

pub fn decode_guarded_wait_request(input: &[u8]) -> Result<(WaitRequest, u64), ProtocolError> {
    if input.len() != WAIT_GUARDED_REQUEST_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok((
        decode_wait_request(&input[..WAIT_REQUEST_LEN])?,
        get_u64(input, WAIT_REQUEST_LEN),
    ))
}

pub fn encode_wait_result(result: WaitResult, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < WAIT_RESULT_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..WAIT_RESULT_LEN].fill(0);
    put_u64(output, 0, result.process_id);
    put_u32(output, 8, result.status);
    Ok(())
}

pub fn decode_wait_result(input: &[u8]) -> Result<WaitResult, ProtocolError> {
    if input.len() != WAIT_RESULT_LEN || get_u32(input, 12) != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(WaitResult {
        process_id: get_u64(input, 0),
        status: get_u32(input, 8),
    })
}

pub fn encode_process_id_request(value: i64, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < PROCESS_ID_REQUEST_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u64(output, 0, value as u64);
    Ok(())
}

pub fn decode_process_id_request(input: &[u8]) -> Result<i64, ProtocolError> {
    if input.len() != PROCESS_ID_REQUEST_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(get_u64(input, 0) as i64)
}

pub fn encode_signal_send_request(
    request: SignalSendRequest,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() < SIGNAL_SEND_REQUEST_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if request.signal > SIGNAL_MAX {
        return Err(ProtocolError::InvalidLength);
    }
    output[..SIGNAL_SEND_REQUEST_LEN].fill(0);
    put_i64(output, 0, request.selector);
    put_u32(output, 8, request.signal);
    Ok(())
}

pub fn decode_signal_send_request(input: &[u8]) -> Result<SignalSendRequest, ProtocolError> {
    if input.len() != SIGNAL_SEND_REQUEST_LEN || get_u32(input, 12) != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    let signal = get_u32(input, 8);
    if signal > SIGNAL_MAX {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(SignalSendRequest {
        selector: get_i64(input, 0),
        signal,
    })
}

pub fn encode_signal_mask(mask: u64, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < SIGNAL_MASK_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u64(output, 0, mask);
    Ok(())
}

/// Contains only a selection mask and async delivery epoch, never an identity
/// or pointer. Sender identity is authenticated by the native IPC endpoint.
pub fn encode_signal_wait_request(
    mask: u64,
    epoch: u64,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() < SIGNAL_WAIT_REQUEST_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u64(output, 0, mask);
    put_u64(output, 8, epoch);
    Ok(())
}

pub fn decode_signal_wait_request(input: &[u8]) -> Result<(u64, u64), ProtocolError> {
    if input.len() != SIGNAL_WAIT_REQUEST_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok((get_u64(input, 0), get_u64(input, 8)))
}

pub fn encode_signal_disposition(
    disposition: SignalDisposition,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() < SIGNAL_DISPOSITION_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if !(1..=SIGNAL_MAX).contains(&disposition.signal)
        || disposition.kind > SIGNAL_DISPOSITION_CAUGHT
        || disposition.child_options & !SIGNAL_CHILD_OPTIONS_ALL != 0
        || (disposition.signal != SIGNAL_CHLD && disposition.child_options != 0)
    {
        return Err(ProtocolError::InvalidLength);
    }
    put_u32(output, 0, disposition.signal);
    put_u32(output, 4, disposition.kind);
    put_u32(output, 8, disposition.child_options);
    put_u32(output, 12, 0);
    Ok(())
}

pub fn decode_signal_disposition(input: &[u8]) -> Result<SignalDisposition, ProtocolError> {
    if input.len() != SIGNAL_DISPOSITION_LEN || get_u32(input, 12) != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    let disposition = SignalDisposition {
        signal: get_u32(input, 0),
        kind: get_u32(input, 4),
        child_options: get_u32(input, 8),
    };
    let mut checked = [0; SIGNAL_DISPOSITION_LEN];
    encode_signal_disposition(disposition, &mut checked)?;
    Ok(disposition)
}

pub fn decode_signal_mask(input: &[u8]) -> Result<u64, ProtocolError> {
    if input.len() != SIGNAL_MASK_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(get_u64(input, 0))
}

pub fn encode_signal_mask_request(
    request: SignalMaskRequest,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() < SIGNAL_THREAD_MASK_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if request.operation > SIGNAL_MASK_INITIALIZE
        || (request.operation == SIGNAL_MASK_QUERY && request.mask != 0)
    {
        return Err(ProtocolError::InvalidLength);
    }
    put_u32(output, 0, request.operation);
    put_u32(output, 4, 0);
    put_u64(output, 8, request.mask);
    Ok(())
}

pub fn decode_signal_mask_request(input: &[u8]) -> Result<SignalMaskRequest, ProtocolError> {
    if input.len() != SIGNAL_THREAD_MASK_LEN || get_u32(input, 4) != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    let request = SignalMaskRequest {
        operation: get_u32(input, 0),
        mask: get_u64(input, 8),
    };
    let mut checked = [0; SIGNAL_THREAD_MASK_LEN];
    encode_signal_mask_request(request, &mut checked)?;
    Ok(request)
}

pub fn encode_signal_child_options(
    options: u32,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() < SIGNAL_CHILD_OPTIONS_LEN || options & !SIGNAL_CHILD_OPTIONS_ALL != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    put_u32(output, 0, options);
    Ok(())
}

pub fn decode_signal_child_options(input: &[u8]) -> Result<u32, ProtocolError> {
    if input.len() != SIGNAL_CHILD_OPTIONS_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let options = get_u32(input, 0);
    if options & !SIGNAL_CHILD_OPTIONS_ALL != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(options)
}

pub fn encode_signal_delivery(
    delivery: SignalDelivery,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() < SIGNAL_DELIVERY_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if delivery.signal > SIGNAL_MAX || (delivery.signal == 0 && delivery.token != 0) {
        return Err(ProtocolError::InvalidLength);
    }
    output[..SIGNAL_DELIVERY_LEN].fill(0);
    put_u32(output, 0, delivery.signal);
    put_u64(output, 8, delivery.token);
    Ok(())
}

pub fn decode_signal_delivery(input: &[u8]) -> Result<SignalDelivery, ProtocolError> {
    if input.len() != SIGNAL_DELIVERY_LEN || get_u32(input, 4) != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    let delivery = SignalDelivery {
        signal: get_u32(input, 0),
        token: get_u64(input, 8),
    };
    if delivery.signal > SIGNAL_MAX || (delivery.signal == 0 && delivery.token != 0) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(delivery)
}

/// Serializes terminal attributes field by field so the provider protocol is
/// independent of the C and Rust structure layouts used by either endpoint.
pub fn encode_terminal_attributes(
    attributes: TerminalAttributes,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() < TERMINAL_ATTRIBUTES_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..TERMINAL_ATTRIBUTES_LEN].fill(0);
    put_u32(output, 0, attributes.input_flags);
    put_u32(output, 4, attributes.output_flags);
    put_u32(output, 8, attributes.control_flags);
    put_u32(output, 12, attributes.local_flags);
    output[16..16 + TERMINAL_CONTROL_CHARACTERS].copy_from_slice(&attributes.control_characters);
    put_u32(output, 48, attributes.input_speed);
    put_u32(output, 52, attributes.output_speed);
    Ok(())
}

pub fn decode_terminal_attributes(input: &[u8]) -> Result<TerminalAttributes, ProtocolError> {
    if input.len() != TERMINAL_ATTRIBUTES_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let mut control_characters = [0; TERMINAL_CONTROL_CHARACTERS];
    control_characters.copy_from_slice(&input[16..16 + TERMINAL_CONTROL_CHARACTERS]);
    Ok(TerminalAttributes {
        input_flags: get_u32(input, 0),
        output_flags: get_u32(input, 4),
        control_flags: get_u32(input, 8),
        local_flags: get_u32(input, 12),
        control_characters,
        input_speed: get_u32(input, 48),
        output_speed: get_u32(input, 52),
    })
}

pub fn encode_terminal_flush(flags: u32, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < TERMINAL_FLUSH_LEN || flags == 0 || flags & !TERMINAL_FLUSH_ALL != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    put_u32(output, 0, flags);
    Ok(())
}

pub fn encode_terminal_flow(action: u32, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < TERMINAL_FLOW_LEN || action > TERMINAL_FLOW_INPUT_START {
        return Err(ProtocolError::InvalidLength);
    }
    put_u32(output, 0, action);
    Ok(())
}

pub fn decode_terminal_flow(input: &[u8]) -> Result<u32, ProtocolError> {
    if input.len() != TERMINAL_FLOW_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let action = get_u32(input, 0);
    if action > TERMINAL_FLOW_INPUT_START {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(action)
}

pub fn decode_terminal_flush(input: &[u8]) -> Result<u32, ProtocolError> {
    if input.len() != TERMINAL_FLUSH_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let flags = get_u32(input, 0);
    if flags == 0 || flags & !TERMINAL_FLUSH_ALL != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(flags)
}

pub fn encode_process_group_request(
    process_id: i64,
    process_group_id: i64,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() < PROCESS_GROUP_REQUEST_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u64(output, 0, process_id as u64);
    put_u64(output, 8, process_group_id as u64);
    Ok(())
}

pub fn decode_process_group_request(input: &[u8]) -> Result<(i64, i64), ProtocolError> {
    if input.len() != PROCESS_GROUP_REQUEST_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok((get_u64(input, 0) as i64, get_u64(input, 8) as i64))
}

pub fn encode_process_info(info: ProcessInfo, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < PROCESS_INFO_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u64(output, 0, info.process_id);
    put_u64(output, 8, info.parent_id);
    put_u64(output, 16, info.process_group_id);
    put_u64(output, 24, info.session_id);
    Ok(())
}

pub fn decode_process_info(input: &[u8]) -> Result<ProcessInfo, ProtocolError> {
    if input.len() != PROCESS_INFO_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(ProcessInfo {
        process_id: get_u64(input, 0),
        parent_id: get_u64(input, 8),
        process_group_id: get_u64(input, 16),
        session_id: get_u64(input, 24),
    })
}

pub fn encode_resource_limit_request(
    request: ResourceLimitRequest,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() < RESOURCE_LIMIT_REQUEST_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if request.flags & !RESOURCE_LIMIT_FLAGS_ALL != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    output[..RESOURCE_LIMIT_REQUEST_LEN].fill(0);
    put_u64(output, 0, request.process_id as u64);
    put_u32(output, 8, request.resource);
    put_u32(output, 12, request.flags);
    put_u64(output, 16, request.limit.soft);
    put_u64(output, 24, request.limit.hard);
    Ok(())
}

pub fn decode_resource_limit_request(input: &[u8]) -> Result<ResourceLimitRequest, ProtocolError> {
    if input.len() != RESOURCE_LIMIT_REQUEST_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let flags = get_u32(input, 12);
    if flags & !RESOURCE_LIMIT_FLAGS_ALL != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(ResourceLimitRequest {
        process_id: get_u64(input, 0) as i64,
        resource: get_u32(input, 8),
        flags,
        limit: ResourceLimit {
            soft: get_u64(input, 16),
            hard: get_u64(input, 24),
        },
    })
}

pub fn encode_resource_limit(limit: ResourceLimit, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < RESOURCE_LIMIT_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u64(output, 0, limit.soft);
    put_u64(output, 8, limit.hard);
    Ok(())
}

pub fn decode_resource_limit(input: &[u8]) -> Result<ResourceLimit, ProtocolError> {
    if input.len() != RESOURCE_LIMIT_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(ResourceLimit {
        soft: get_u64(input, 0),
        hard: get_u64(input, 8),
    })
}

pub fn encode_file_length(value: u64, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < FILE_LENGTH_PAYLOAD_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u64(output, 0, value);
    Ok(())
}

pub fn decode_file_length(input: &[u8]) -> Result<u64, ProtocolError> {
    if input.len() != FILE_LENGTH_PAYLOAD_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(get_u64(input, 0))
}

pub fn encode_file_flags(value: u32, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < FILE_FLAGS_PAYLOAD_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, value);
    Ok(())
}

pub fn decode_file_flags(input: &[u8]) -> Result<u32, ProtocolError> {
    if input.len() != FILE_FLAGS_PAYLOAD_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(get_u32(input, 0))
}

pub fn encode_file_flags_update(
    mask: u32,
    flags: u32,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if mask & !MUTABLE_STATUS_FLAGS != 0 || flags & !mask != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    if output.len() < FILE_FLAGS_UPDATE_PAYLOAD_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, mask);
    put_u32(output, 4, flags);
    Ok(())
}

pub fn decode_file_flags_update(input: &[u8]) -> Result<(u32, u32), ProtocolError> {
    if input.len() != FILE_FLAGS_UPDATE_PAYLOAD_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let mask = get_u32(input, 0);
    let flags = get_u32(input, 4);
    if mask & !MUTABLE_STATUS_FLAGS != 0 || flags & !mask != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    Ok((mask, flags))
}

pub fn encode_open_at(
    request: OpenAtRequest<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let path = request.path.as_bytes();
    if path.is_empty()
        || path.len() > MAX_PATH_LEN
        || path.contains(&0)
        || request.options & !OPEN_OPTIONS_ALL != 0
    {
        return Err(ProtocolError::InvalidLength);
    }
    let total = OPEN_AT_HEADER_LEN
        .checked_add(path.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..OPEN_AT_HEADER_LEN].fill(0);
    output[0] = request.base as u8;
    put_u32(output, 4, request.options);
    put_u32(output, 8, request.mode);
    put_u32(output, 12, path.len() as u32);
    output[OPEN_AT_HEADER_LEN..total].copy_from_slice(path);
    Ok(total)
}

pub fn decode_open_at(input: &[u8]) -> Result<OpenAtRequest<'_>, ProtocolError> {
    if input.len() < OPEN_AT_HEADER_LEN || input[1..4] != [0; 3] {
        return Err(ProtocolError::InvalidLength);
    }
    let base = OpenBase::from_raw(input[0]).ok_or(ProtocolError::InvalidLength)?;
    let options = get_u32(input, 4);
    if options & !OPEN_OPTIONS_ALL != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    let path_len = get_u32(input, 12) as usize;
    if path_len == 0 || path_len > MAX_PATH_LEN || input.len() != OPEN_AT_HEADER_LEN + path_len {
        return Err(ProtocolError::InvalidLength);
    }
    let path_bytes = &input[OPEN_AT_HEADER_LEN..];
    if path_bytes.contains(&0) {
        return Err(ProtocolError::InvalidLength);
    }
    let path = core::str::from_utf8(path_bytes).map_err(|_| ProtocolError::InvalidLength)?;
    Ok(OpenAtRequest {
        base,
        options,
        mode: get_u32(input, 8),
        path,
    })
}

pub fn encode_stat_at(
    request: StatAtRequest<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let path = request.path.as_bytes();
    if path.is_empty()
        || path.len() > MAX_PATH_LEN
        || path.contains(&0)
        || request.flags & !STAT_FLAGS_ALL != 0
    {
        return Err(ProtocolError::InvalidLength);
    }
    let total = STAT_AT_HEADER_LEN
        .checked_add(path.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..STAT_AT_HEADER_LEN].fill(0);
    output[0] = request.base as u8;
    put_u32(output, 4, request.flags);
    put_u32(output, 8, path.len() as u32);
    output[STAT_AT_HEADER_LEN..total].copy_from_slice(path);
    Ok(total)
}

pub fn decode_stat_at(input: &[u8]) -> Result<StatAtRequest<'_>, ProtocolError> {
    if input.len() < STAT_AT_HEADER_LEN || input[1..4] != [0; 3] {
        return Err(ProtocolError::InvalidLength);
    }
    let base = OpenBase::from_raw(input[0]).ok_or(ProtocolError::InvalidLength)?;
    let flags = get_u32(input, 4);
    if flags & !STAT_FLAGS_ALL != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    let path_len = get_u32(input, 8) as usize;
    if path_len == 0 || path_len > MAX_PATH_LEN || input.len() != STAT_AT_HEADER_LEN + path_len {
        return Err(ProtocolError::InvalidLength);
    }
    let path_bytes = &input[STAT_AT_HEADER_LEN..];
    if path_bytes.contains(&0) {
        return Err(ProtocolError::InvalidLength);
    }
    let path = core::str::from_utf8(path_bytes).map_err(|_| ProtocolError::InvalidLength)?;
    Ok(StatAtRequest { base, flags, path })
}

pub fn encode_rename_at(
    request: RenameAtRequest<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let old_path = request.old_path.as_bytes();
    let new_path = request.new_path.as_bytes();
    if old_path.is_empty()
        || new_path.is_empty()
        || old_path.len() > MAX_PATH_LEN
        || new_path.len() > MAX_PATH_LEN
        || old_path.contains(&0)
        || new_path.contains(&0)
    {
        return Err(ProtocolError::InvalidLength);
    }
    let total = RENAME_AT_HEADER_LEN
        .checked_add(old_path.len())
        .and_then(|length| length.checked_add(new_path.len()))
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..RENAME_AT_HEADER_LEN].fill(0);
    output[0] = request.old_base as u8;
    output[1] = request.new_base as u8;
    put_u32(output, 8, old_path.len() as u32);
    put_u32(output, 12, new_path.len() as u32);
    output[RENAME_AT_HEADER_LEN..RENAME_AT_HEADER_LEN + old_path.len()].copy_from_slice(old_path);
    output[RENAME_AT_HEADER_LEN + old_path.len()..total].copy_from_slice(new_path);
    Ok(total)
}

pub fn decode_rename_at(input: &[u8]) -> Result<RenameAtRequest<'_>, ProtocolError> {
    if input.len() < RENAME_AT_HEADER_LEN || input[2..8] != [0; 6] {
        return Err(ProtocolError::InvalidLength);
    }
    let old_base = OpenBase::from_raw(input[0]).ok_or(ProtocolError::InvalidLength)?;
    let new_base = OpenBase::from_raw(input[1]).ok_or(ProtocolError::InvalidLength)?;
    let old_len = get_u32(input, 8) as usize;
    let new_len = get_u32(input, 12) as usize;
    if old_len == 0
        || new_len == 0
        || old_len > MAX_PATH_LEN
        || new_len > MAX_PATH_LEN
        || input.len() != RENAME_AT_HEADER_LEN + old_len + new_len
    {
        return Err(ProtocolError::InvalidLength);
    }
    let old_bytes = &input[RENAME_AT_HEADER_LEN..RENAME_AT_HEADER_LEN + old_len];
    let new_bytes = &input[RENAME_AT_HEADER_LEN + old_len..];
    if old_bytes.contains(&0) || new_bytes.contains(&0) {
        return Err(ProtocolError::InvalidLength);
    }
    let old_path = core::str::from_utf8(old_bytes).map_err(|_| ProtocolError::InvalidLength)?;
    let new_path = core::str::from_utf8(new_bytes).map_err(|_| ProtocolError::InvalidLength)?;
    Ok(RenameAtRequest {
        old_base,
        new_base,
        old_path,
        new_path,
    })
}

pub fn encode_link_at(
    request: LinkAtRequest<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let old_path = request.old_path.as_bytes();
    let new_path = request.new_path.as_bytes();
    if old_path.is_empty()
        || new_path.is_empty()
        || old_path.len() > MAX_PATH_LEN
        || new_path.len() > MAX_PATH_LEN
        || old_path.contains(&0)
        || new_path.contains(&0)
        || request.flags & !LINK_FLAGS_ALL != 0
    {
        return Err(ProtocolError::InvalidLength);
    }
    let total = LINK_AT_HEADER_LEN
        .checked_add(old_path.len())
        .and_then(|length| length.checked_add(new_path.len()))
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..LINK_AT_HEADER_LEN].fill(0);
    output[0] = request.old_base as u8;
    output[1] = request.new_base as u8;
    put_u32(output, 4, request.flags);
    put_u32(output, 8, old_path.len() as u32);
    put_u32(output, 12, new_path.len() as u32);
    output[LINK_AT_HEADER_LEN..LINK_AT_HEADER_LEN + old_path.len()].copy_from_slice(old_path);
    output[LINK_AT_HEADER_LEN + old_path.len()..total].copy_from_slice(new_path);
    Ok(total)
}

pub fn decode_link_at(input: &[u8]) -> Result<LinkAtRequest<'_>, ProtocolError> {
    if input.len() < LINK_AT_HEADER_LEN || input[2..4] != [0; 2] {
        return Err(ProtocolError::InvalidLength);
    }
    let old_base = OpenBase::from_raw(input[0]).ok_or(ProtocolError::InvalidLength)?;
    let new_base = OpenBase::from_raw(input[1]).ok_or(ProtocolError::InvalidLength)?;
    let flags = get_u32(input, 4);
    let old_len = get_u32(input, 8) as usize;
    let new_len = get_u32(input, 12) as usize;
    if flags & !LINK_FLAGS_ALL != 0
        || old_len == 0
        || new_len == 0
        || old_len > MAX_PATH_LEN
        || new_len > MAX_PATH_LEN
        || input.len() != LINK_AT_HEADER_LEN + old_len + new_len
    {
        return Err(ProtocolError::InvalidLength);
    }
    let old_bytes = &input[LINK_AT_HEADER_LEN..LINK_AT_HEADER_LEN + old_len];
    let new_bytes = &input[LINK_AT_HEADER_LEN + old_len..];
    if old_bytes.contains(&0) || new_bytes.contains(&0) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(LinkAtRequest {
        old_base,
        new_base,
        flags,
        old_path: core::str::from_utf8(old_bytes).map_err(|_| ProtocolError::InvalidLength)?,
        new_path: core::str::from_utf8(new_bytes).map_err(|_| ProtocolError::InvalidLength)?,
    })
}

pub fn encode_truncate_at(
    request: TruncateAtRequest<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let path = request.path.as_bytes();
    if path.is_empty() || path.len() > MAX_PATH_LEN || path.contains(&0) {
        return Err(ProtocolError::InvalidLength);
    }
    let total = TRUNCATE_AT_HEADER_LEN
        .checked_add(path.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..TRUNCATE_AT_HEADER_LEN].fill(0);
    output[0] = request.base as u8;
    put_u64(output, 4, request.length);
    put_u32(output, 12, path.len() as u32);
    output[TRUNCATE_AT_HEADER_LEN..total].copy_from_slice(path);
    Ok(total)
}

pub fn decode_truncate_at(input: &[u8]) -> Result<TruncateAtRequest<'_>, ProtocolError> {
    if input.len() < TRUNCATE_AT_HEADER_LEN || input[1..4] != [0; 3] {
        return Err(ProtocolError::InvalidLength);
    }
    let base = OpenBase::from_raw(input[0]).ok_or(ProtocolError::InvalidLength)?;
    let length = get_u64(input, 4);
    let path_len = get_u32(input, 12) as usize;
    if path_len == 0 || path_len > MAX_PATH_LEN || input.len() != TRUNCATE_AT_HEADER_LEN + path_len
    {
        return Err(ProtocolError::InvalidLength);
    }
    let path_bytes = &input[TRUNCATE_AT_HEADER_LEN..];
    if path_bytes.contains(&0) {
        return Err(ProtocolError::InvalidLength);
    }
    let path = core::str::from_utf8(path_bytes).map_err(|_| ProtocolError::InvalidLength)?;
    Ok(TruncateAtRequest { base, length, path })
}

pub fn encode_symlink_at(
    request: SymlinkAtRequest<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let target = request.target.as_bytes();
    let link_path = request.link_path.as_bytes();
    if target.is_empty()
        || link_path.is_empty()
        || target.len() > MAX_PATH_LEN
        || link_path.len() > MAX_PATH_LEN
        || target.contains(&0)
        || link_path.contains(&0)
    {
        return Err(ProtocolError::InvalidLength);
    }
    let total = SYMLINK_AT_HEADER_LEN
        .checked_add(target.len())
        .and_then(|length| length.checked_add(link_path.len()))
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..SYMLINK_AT_HEADER_LEN].fill(0);
    output[0] = request.base as u8;
    put_u32(output, 4, target.len() as u32);
    put_u32(output, 8, link_path.len() as u32);
    output[SYMLINK_AT_HEADER_LEN..SYMLINK_AT_HEADER_LEN + target.len()].copy_from_slice(target);
    output[SYMLINK_AT_HEADER_LEN + target.len()..total].copy_from_slice(link_path);
    Ok(total)
}

pub fn decode_symlink_at(input: &[u8]) -> Result<SymlinkAtRequest<'_>, ProtocolError> {
    if input.len() < SYMLINK_AT_HEADER_LEN || input[1..4] != [0; 3] || input[12..16] != [0; 4] {
        return Err(ProtocolError::InvalidLength);
    }
    let base = OpenBase::from_raw(input[0]).ok_or(ProtocolError::InvalidLength)?;
    let target_len = get_u32(input, 4) as usize;
    let link_len = get_u32(input, 8) as usize;
    if target_len == 0
        || link_len == 0
        || target_len > MAX_PATH_LEN
        || link_len > MAX_PATH_LEN
        || input.len() != SYMLINK_AT_HEADER_LEN + target_len + link_len
    {
        return Err(ProtocolError::InvalidLength);
    }
    let target_bytes = &input[SYMLINK_AT_HEADER_LEN..SYMLINK_AT_HEADER_LEN + target_len];
    let link_bytes = &input[SYMLINK_AT_HEADER_LEN + target_len..];
    if target_bytes.contains(&0) || link_bytes.contains(&0) {
        return Err(ProtocolError::InvalidLength);
    }
    let target = core::str::from_utf8(target_bytes).map_err(|_| ProtocolError::InvalidLength)?;
    let link_path = core::str::from_utf8(link_bytes).map_err(|_| ProtocolError::InvalidLength)?;
    Ok(SymlinkAtRequest {
        base,
        target,
        link_path,
    })
}

pub fn encode_chown_at(
    request: ChownAtRequest<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let path = request.path.as_bytes();
    if path.is_empty()
        || path.len() > MAX_PATH_LEN
        || path.contains(&0)
        || request.flags & !CHOWN_FLAGS_ALL != 0
    {
        return Err(ProtocolError::InvalidLength);
    }
    let total = CHOWN_AT_HEADER_LEN
        .checked_add(path.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..CHOWN_AT_HEADER_LEN].fill(0);
    output[0] = request.base as u8;
    put_u32(output, 4, request.flags);
    put_u32(output, 8, request.uid);
    put_u32(output, 12, request.gid);
    put_u32(output, 16, path.len() as u32);
    output[CHOWN_AT_HEADER_LEN..total].copy_from_slice(path);
    Ok(total)
}

pub fn decode_chown_at(input: &[u8]) -> Result<ChownAtRequest<'_>, ProtocolError> {
    if input.len() < CHOWN_AT_HEADER_LEN || input[1..4] != [0; 3] {
        return Err(ProtocolError::InvalidLength);
    }
    let base = OpenBase::from_raw(input[0]).ok_or(ProtocolError::InvalidLength)?;
    let flags = get_u32(input, 4);
    let path_len = get_u32(input, 16) as usize;
    if flags & !CHOWN_FLAGS_ALL != 0
        || path_len == 0
        || path_len > MAX_PATH_LEN
        || input.len() != CHOWN_AT_HEADER_LEN + path_len
    {
        return Err(ProtocolError::InvalidLength);
    }
    let path_bytes = &input[CHOWN_AT_HEADER_LEN..];
    if path_bytes.contains(&0) {
        return Err(ProtocolError::InvalidLength);
    }
    let path = core::str::from_utf8(path_bytes).map_err(|_| ProtocolError::InvalidLength)?;
    Ok(ChownAtRequest {
        base,
        flags,
        uid: get_u32(input, 8),
        gid: get_u32(input, 12),
        path,
    })
}

pub fn encode_file_owner(uid: u32, gid: u32, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < FILE_OWNER_PAYLOAD_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    put_u32(output, 0, uid);
    put_u32(output, 4, gid);
    Ok(())
}

pub fn decode_file_owner(input: &[u8]) -> Result<(u32, u32), ProtocolError> {
    if input.len() != FILE_OWNER_PAYLOAD_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    Ok((get_u32(input, 0), get_u32(input, 4)))
}

pub fn encode_access_at(
    request: AccessAtRequest<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let path = request.path.as_bytes();
    if path.is_empty()
        || path.len() > MAX_PATH_LEN
        || path.contains(&0)
        || request.flags & !ACCESS_FLAGS_ALL != 0
        || request.modes & !ACCESS_MODES_ALL != 0
    {
        return Err(ProtocolError::InvalidLength);
    }
    let total = ACCESS_AT_HEADER_LEN
        .checked_add(path.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if output.len() < total {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..ACCESS_AT_HEADER_LEN].fill(0);
    output[0] = request.base as u8;
    put_u32(output, 4, request.flags);
    put_u32(output, 8, request.modes);
    put_u32(output, 12, path.len() as u32);
    output[ACCESS_AT_HEADER_LEN..total].copy_from_slice(path);
    Ok(total)
}

pub fn decode_access_at(input: &[u8]) -> Result<AccessAtRequest<'_>, ProtocolError> {
    if input.len() < ACCESS_AT_HEADER_LEN || input[1..4] != [0; 3] {
        return Err(ProtocolError::InvalidLength);
    }
    let base = OpenBase::from_raw(input[0]).ok_or(ProtocolError::InvalidLength)?;
    let flags = get_u32(input, 4);
    let modes = get_u32(input, 8);
    if flags & !ACCESS_FLAGS_ALL != 0 || modes & !ACCESS_MODES_ALL != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    let path_len = get_u32(input, 12) as usize;
    if path_len == 0 || path_len > MAX_PATH_LEN || input.len() != ACCESS_AT_HEADER_LEN + path_len {
        return Err(ProtocolError::InvalidLength);
    }
    let path_bytes = &input[ACCESS_AT_HEADER_LEN..];
    if path_bytes.contains(&0) {
        return Err(ProtocolError::InvalidLength);
    }
    let path = core::str::from_utf8(path_bytes).map_err(|_| ProtocolError::InvalidLength)?;
    Ok(AccessAtRequest {
        base,
        flags,
        modes,
        path,
    })
}

pub fn encode_file_status(status: FileStatus, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < FILE_STATUS_LEN || !timestamps_are_valid(&status) {
        return Err(if output.len() < FILE_STATUS_LEN {
            ProtocolError::BufferTooSmall
        } else {
            ProtocolError::InvalidLength
        });
    }
    output[..FILE_STATUS_LEN].fill(0);
    put_u64(output, 0, status.device);
    put_u64(output, 8, status.inode);
    put_u32(output, 16, status.mode);
    put_u32(output, 20, status.link_count);
    put_u32(output, 24, status.uid);
    put_u32(output, 28, status.gid);
    put_u64(output, 32, status.special_device);
    put_i64(output, 40, status.size);
    put_i64(output, 48, status.block_size);
    put_i64(output, 56, status.blocks);
    put_i64(output, 64, status.access_time_seconds);
    put_i64(output, 72, status.access_time_nanoseconds);
    put_i64(output, 80, status.modification_time_seconds);
    put_i64(output, 88, status.modification_time_nanoseconds);
    put_i64(output, 96, status.change_time_seconds);
    put_i64(output, 104, status.change_time_nanoseconds);
    Ok(())
}

pub fn decode_file_status(input: &[u8]) -> Result<FileStatus, ProtocolError> {
    if input.len() != FILE_STATUS_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let status = FileStatus {
        device: get_u64(input, 0),
        inode: get_u64(input, 8),
        mode: get_u32(input, 16),
        link_count: get_u32(input, 20),
        uid: get_u32(input, 24),
        gid: get_u32(input, 28),
        special_device: get_u64(input, 32),
        size: get_i64(input, 40),
        block_size: get_i64(input, 48),
        blocks: get_i64(input, 56),
        access_time_seconds: get_i64(input, 64),
        access_time_nanoseconds: get_i64(input, 72),
        modification_time_seconds: get_i64(input, 80),
        modification_time_nanoseconds: get_i64(input, 88),
        change_time_seconds: get_i64(input, 96),
        change_time_nanoseconds: get_i64(input, 104),
    };
    if !timestamps_are_valid(&status) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(status)
}

fn timestamps_are_valid(status: &FileStatus) -> bool {
    [
        status.access_time_nanoseconds,
        status.modification_time_nanoseconds,
        status.change_time_nanoseconds,
    ]
    .into_iter()
    .all(|nanoseconds| (0..1_000_000_000).contains(&nanoseconds))
}

fn put_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_i64(output: &mut [u8], offset: usize, value: i64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([input[offset], input[offset + 1]])
}

fn get_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap())
}

fn get_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap())
}

fn get_i64(input: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(input[offset..offset + 8].try_into().unwrap())
}
