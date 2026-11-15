//! Process-local POSIX signal ABI. These types never travel over service IPC.
use crate::protocol;
use mnu_abi::{MemoryFaultCause, ThreadInitialRegisters, ThreadUpcallSnapshot};

#[cfg(target_arch = "x86_64")]
#[path = "signal_context/x86_64.rs"]
mod machine;
#[cfg(target_arch = "aarch64")]
#[path = "signal_context/aarch64.rs"]
mod machine;
pub use machine::*;

pub const SI_USER: i32 = 1;
pub const SI_TIMER: i32 = 3;
pub const SI_KERNEL: i32 = 128;
// newlib's existing generic SI_* sources occupy 1..=5. Keep synchronous
// fault codes disjoint so kill(SIGSEGV) cannot look like an address fault.
pub const SEGV_MAPERR: i32 = 0x100;
pub const SEGV_ACCERR: i32 = 0x101;
pub const BUS_ADRERR: i32 = 0x101;
pub const BUS_OBJERR: i32 = 0x102;
pub const CLD_EXITED: i32 = 0x100;
pub const CLD_KILLED: i32 = 0x101;
pub const CLD_DUMPED: i32 = 0x102;
pub const CLD_TRAPPED: i32 = 0x103;
pub const CLD_STOPPED: i32 = 0x104;
pub const CLD_CONTINUED: i32 = 0x105;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InfoError {
    InvalidSignal,
    InvalidOrigin,
    Overflow,
    MissingDetail,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union SigValue {
    pub sival_int: i32,
    pub sival_ptr: usize,
}

/// Matches the mochiOS newlib siginfo_t, including its 16-bit uid_t.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SigInfo {
    pub si_signo: i32,
    pub si_code: i32,
    pub si_value: SigValue,
    pub si_errno: i32,
    pub si_pid: i32,
    pub si_uid: u16,
    pub reserved_uid: u16,
    pub si_status: i32,
    pub si_addr: usize,
}

impl SigInfo {
    fn empty(signal: u32, code: i32) -> Self {
        Self {
            si_signo: signal as i32,
            si_code: code,
            si_value: SigValue { sival_ptr: 0 },
            si_errno: 0,
            si_pid: 0,
            si_uid: 0,
            reserved_uid: 0,
            si_status: 0,
            si_addr: 0,
        }
    }

    /// Origin fields come from the authenticated delivery, not request bytes.
    /// Child status must be present in the recorded notification; fault
    /// metadata needs its dedicated constructor, never a fabricated default.
    pub fn from_origin(
        signal: u32,
        origin: protocol::signal_origin::Origin,
    ) -> Result<Self, InfoError> {
        if signal == 0 || signal > protocol::SIGNAL_MAX {
            return Err(InfoError::InvalidSignal);
        }
        let mut result = Self::empty(signal, SI_USER);
        if origin.source == protocol::signal_origin::CHILD && origin.child.event == 0 {
            return Err(InfoError::MissingDetail);
        }
        protocol::signal_origin::encode(origin, &mut [0; protocol::signal_origin::MAX_LEN])
            .map_err(|_| InfoError::InvalidOrigin)?;
        match origin.source {
            protocol::signal_origin::USER if origin.process_id != 0 => {
                result.si_pid =
                    i32::try_from(origin.process_id).map_err(|_| InfoError::Overflow)?;
                result.si_uid = u16::try_from(origin.real_uid).map_err(|_| InfoError::Overflow)?;
            }
            protocol::signal_origin::SYSTEM if origin.process_id == 0 && origin.real_uid == 0 => {
                result.si_code = SI_KERNEL;
            }
            protocol::signal_origin::CHILD => {
                if signal != protocol::SIGNAL_CHLD {
                    return Err(InfoError::InvalidSignal);
                }
                result.si_code = match origin.child.event {
                    protocol::signal_origin::EXITED => CLD_EXITED,
                    protocol::signal_origin::KILLED => CLD_KILLED,
                    protocol::signal_origin::DUMPED => CLD_DUMPED,
                    protocol::signal_origin::TRAPPED => CLD_TRAPPED,
                    protocol::signal_origin::STOPPED => CLD_STOPPED,
                    protocol::signal_origin::CONTINUED => CLD_CONTINUED,
                    _ => return Err(InfoError::MissingDetail),
                };
                result.si_pid =
                    i32::try_from(origin.process_id).map_err(|_| InfoError::Overflow)?;
                result.si_uid = u16::try_from(origin.real_uid).map_err(|_| InfoError::Overflow)?;
                result.si_status = origin.child.status as i32;
            }
            protocol::signal_origin::FAULT => {
                return Err(InfoError::MissingDetail);
            }
            protocol::signal_origin::TIMER => {
                // A service value token is not a C sigval. Only the runtime's
                // process-local registry may resolve the application value.
                return Err(InfoError::MissingDetail);
            }
            _ => return Err(InfoError::InvalidOrigin),
        }
        Ok(result)
    }

    /// The caller supplies locally resolved sigval bits, not the wire token.
    /// Keeping resolution separate prevents a cookie from becoming a pointer.
    pub fn from_timer_origin(
        signal: u32,
        origin: protocol::signal_origin::Origin,
        resolved_value: usize,
    ) -> Result<Self, InfoError> {
        if signal == 0 || signal > protocol::SIGNAL_MAX {
            return Err(InfoError::InvalidSignal);
        }
        protocol::signal_origin::encode(origin, &mut [0; protocol::signal_origin::MAX_LEN])
            .map_err(|_| InfoError::InvalidOrigin)?;
        if origin.source != protocol::signal_origin::TIMER || origin.timer.is_none() {
            return Err(InfoError::MissingDetail);
        }
        let mut result = Self::empty(signal, SI_TIMER);
        result.si_value = SigValue {
            sival_ptr: resolved_value,
        };
        Ok(result)
    }

    pub fn memory_fault(cause: u64, address: usize) -> Result<Self, InfoError> {
        let (signal, code) = match cause {
            value if value == MemoryFaultCause::Unmapped as u64 => {
                (protocol::SIGNAL_SEGV, SEGV_MAPERR)
            }
            value if value == MemoryFaultCause::AccessDenied as u64 => {
                (protocol::SIGNAL_SEGV, SEGV_ACCERR)
            }
            value if value == MemoryFaultCause::OutsideBacking as u64 => {
                (protocol::SIGNAL_BUS, BUS_ADRERR)
            }
            value
                if value == MemoryFaultCause::BackingFailure as u64
                    || value == MemoryFaultCause::ResourceUnavailable as u64 =>
            {
                (protocol::SIGNAL_BUS, BUS_OBJERR)
            }
            value if value == MemoryFaultCause::Unresolved as u64 => {
                (protocol::SIGNAL_SEGV, SI_KERNEL)
            }
            _ => return Err(InfoError::InvalidOrigin),
        };
        let mut info = Self::empty(signal, code);
        info.si_addr = address;
        Ok(info)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stack {
    pub ss_sp: usize,
    pub ss_flags: i32,
    pub ss_size: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UContext {
    pub uc_flags: u64,
    pub uc_link: usize,
    pub uc_sigmask: u64,
    pub uc_stack: Stack,
    pub uc_mcontext: MachineContext,
}
