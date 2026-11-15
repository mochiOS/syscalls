use super::*;

pub const REG_X0: usize = 0;
pub const REG_SP: usize = 31;
pub const REG_PC: usize = 32;
pub const REG_PSTATE: usize = 33;
pub const NGREG: usize = 34;

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MachineContext {
    pub gregs: [u64; NGREG],
    pub fpregs: [u8; 512],
    pub fpcr: u64,
    pub fpsr: u64,
}

impl MachineContext {
    /// Privileged/reserved flags and non-base FP control bits cannot be restored
    /// by a synchronous userspace return. Native mnu return validates again.
    pub fn checked_return(&self, _original: &Self) -> Option<Self> {
        const FPCR: u64 = (31 << 22) | (1 << 15) | (31 << 8);
        const FPSR: u64 = (1 << 27) | (1 << 7) | 31;
        (self.gregs[REG_PC] != 0
            && self.gregs[REG_PC] >> 47 == 0
            && self.gregs[REG_PC] & 3 == 0
            && self.gregs[REG_SP] >= 16
            && self.gregs[REG_SP] >> 47 == 0
            && self.gregs[REG_SP] & 15 == 0
            && self.gregs[REG_PSTATE] & !(15 << 28) == 0
            && self.fpcr & !FPCR == 0
            && self.fpsr & !FPSR == 0)
            .then_some(*self)
    }
}

impl UContext {
    pub fn from_native(native: &ThreadUpcallSnapshot, mask: u64, stack: Stack) -> Self {
        let mut gregs = [0; NGREG];
        gregs[0] = native.argument;
        gregs[1..31].copy_from_slice(&native.registers.x);
        gregs[REG_SP] = native.stack_pointer;
        gregs[REG_PC] = native.instruction;
        gregs[REG_PSTATE] = native.pstate;
        Self {
            uc_flags: 0,
            uc_link: 0,
            uc_sigmask: mask,
            uc_stack: stack,
            uc_mcontext: MachineContext {
                gregs,
                fpregs: native.fp_state,
                fpcr: native.fpcr,
                fpsr: native.fpsr,
            },
        }
    }

    pub fn native_snapshot(&self) -> ThreadUpcallSnapshot {
        let context = &self.uc_mcontext;
        ThreadUpcallSnapshot {
            instruction: context.gregs[REG_PC],
            stack_pointer: context.gregs[REG_SP],
            pstate: context.gregs[REG_PSTATE],
            argument: context.gregs[REG_X0],
            registers: ThreadInitialRegisters {
                x: core::array::from_fn(|i| context.gregs[i + 1]),
            },
            fp_state: context.fpregs,
            fpcr: context.fpcr,
            fpsr: context.fpsr,
        }
    }
}
