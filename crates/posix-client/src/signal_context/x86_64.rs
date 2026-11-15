use super::*;

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

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MachineContext {
    pub gregs: [u64; NGREG],
    pub fpregs: [u8; 512],
}

impl MachineContext {
    /// Checks a synchronous userspace continuation against the CPU's original
    /// MXCSR capability mask. Native upcall return is also independently
    /// validated by mnu; this protects the userspace FXRSTOR path.
    pub fn checked_return(&self, original: &Self) -> Option<Self> {
        const REQUIRED: u64 = (1 << 1) | (1 << 9);
        const ALLOWED: u64 = REQUIRED
            | 1
            | (1 << 2)
            | (1 << 4)
            | (1 << 6)
            | (1 << 7)
            | (1 << 8)
            | (1 << 10)
            | (1 << 11)
            | (1 << 16)
            | (1 << 18)
            | (1 << 21);
        if self.gregs[REG_RIP] == 0
            || self.gregs[REG_RIP] >> 47 != 0
            || self.gregs[REG_RSP] < 16
            || self.gregs[REG_RSP] >> 47 != 0
            || self.gregs[REG_EFL] & REQUIRED != REQUIRED
            || self.gregs[REG_EFL] & !ALLOWED != 0
        {
            return None;
        }
        let mask = u32::from_le_bytes(original.fpregs[28..32].try_into().ok()?);
        let mask = if mask == 0 { 0xffbf } else { mask };
        let mxcsr = u32::from_le_bytes(self.fpregs[24..28].try_into().ok()?);
        if mxcsr & !mask != 0 {
            return None;
        }
        let mut selected = *self;
        selected.fpregs[28..32].copy_from_slice(&mask.to_le_bytes());
        Some(selected)
    }
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
