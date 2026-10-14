//! Process-local POSIX signal ABI. These types never travel over service IPC.
use crate::protocol;
use mnu_abi::{MemoryFaultCause, ThreadInitialRegisters, ThreadUpcallSnapshot};

pub const SI_USER: i32 = 1;
pub const SI_KERNEL: i32 = 128;
// newlib's existing generic SI_* sources occupy 1..=5. Keep synchronous
// fault codes disjoint so kill(SIGSEGV) cannot look like an address fault.
pub const SEGV_MAPERR: i32 = 0x100;
pub const SEGV_ACCERR: i32 = 0x101;
pub const BUS_ADRERR: i32 = 0x101;
pub const BUS_OBJERR: i32 = 0x102;
pub const REG_R8: usize = 0;
pub const REG_R9: usize = 1;
pub const REG_R10: usize = 2;
pub const REG_R11: usize = 3;
pub const REG_R12: usize = 4;
pub const REG_R13: usize = 5;
pub const REG_R14: usize = 6;
pub const REG_R15: usize = 7;
pub const REG_RDI: usize = 8;
pub const REG_RSI: usize = 9;
pub const REG_RBP: usize = 10;
pub const REG_RBX: usize = 11;
pub const REG_RDX: usize = 12;
pub const REG_RAX: usize = 13;
pub const REG_RCX: usize = 14;
pub const REG_RSP: usize = 15;
pub const REG_RIP: usize = 16;
pub const REG_EFL: usize = 17;
pub const NGREG: usize = 18;

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
    /// Child status and fault metadata need their dedicated constructors;
    /// never manufacture them from a generic source tag.
    pub fn from_origin(
        signal: u32,
        origin: protocol::signal_origin::Origin,
    ) -> Result<Self, InfoError> {
        if signal == 0 || signal > protocol::SIGNAL_MAX {
            return Err(InfoError::InvalidSignal);
        }
        let mut result = Self::empty(signal, SI_USER);
        match origin.source {
            protocol::signal_origin::USER if origin.process_id != 0 => {
                result.si_pid =
                    i32::try_from(origin.process_id).map_err(|_| InfoError::Overflow)?;
                result.si_uid = u16::try_from(origin.real_uid).map_err(|_| InfoError::Overflow)?;
            }
            protocol::signal_origin::SYSTEM if origin.process_id == 0 && origin.real_uid == 0 => {
                result.si_code = SI_KERNEL;
            }
            protocol::signal_origin::CHILD | protocol::signal_origin::FAULT => {
                return Err(InfoError::MissingDetail);
            }
            _ => return Err(InfoError::InvalidOrigin),
        }
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

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MachineContext {
    pub gregs: [u64; NGREG],
    pub fpregs: [u8; 512],
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

impl UContext {
    /// The mask and alternate-stack state belong to the POSIX layer. The
    /// native snapshot contains CPU state only and supplies neither policy.
    pub fn from_native(native: &ThreadUpcallSnapshot, mask: u64, stack: Stack) -> Self {
        let r = &native.registers;
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_sigmask: mask,
            uc_stack: stack,
            uc_mcontext: MachineContext {
                gregs: [
                    r.r8,
                    r.r9,
                    r.r10,
                    r.r11,
                    r.r12,
                    r.r13,
                    r.r14,
                    r.r15,
                    native.argument,
                    r.rsi,
                    r.rbp,
                    r.rbx,
                    r.rdx,
                    r.rax,
                    r.rcx,
                    native.stack_pointer,
                    native.instruction,
                    native.rflags,
                ],
                fpregs: native.fx_state,
            },
        }
    }

    /// Only CPU state is converted. The POSIX layer must restore uc_sigmask
    /// separately, and native ThreadUpcallReturnContext validates the result.
    pub fn native_snapshot(&self) -> ThreadUpcallSnapshot {
        let r = &self.uc_mcontext.gregs;
        ThreadUpcallSnapshot {
            instruction: r[REG_RIP],
            stack_pointer: r[REG_RSP],
            rflags: r[REG_EFL],
            argument: r[REG_RDI],
            registers: ThreadInitialRegisters {
                rax: r[REG_RAX],
                rbx: r[REG_RBX],
                rcx: r[REG_RCX],
                rdx: r[REG_RDX],
                rsi: r[REG_RSI],
                rbp: r[REG_RBP],
                r8: r[REG_R8],
                r9: r[REG_R9],
                r10: r[REG_R10],
                r11: r[REG_R11],
                r12: r[REG_R12],
                r13: r[REG_R13],
                r14: r[REG_R14],
                r15: r[REG_R15],
            },
            fx_state: self.uc_mcontext.fpregs,
        }
    }
}
