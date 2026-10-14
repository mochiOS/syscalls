//! Thread-owned POSIX alternate-stack configuration. No kernel stack policy.
use crate::signal_context::Stack;
use core::{
    ffi::c_void,
    sync::atomic::{AtomicUsize, Ordering},
};

pub const SS_ONSTACK: i32 = 1;
pub const SS_DISABLE: i32 = 2;
pub const MIN_SIZE: usize = 2048;
pub const SA_ONSTACK: i32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackError {
    InUse,
    Flags,
    TooSmall,
    Range,
}

pub struct AlternateStack {
    base: AtomicUsize,
    size: AtomicUsize,
}

impl AlternateStack {
    pub const fn new() -> Self {
        Self {
            base: AtomicUsize::new(0),
            size: AtomicUsize::new(0),
        }
    }

    /// Only the owning thread accesses its configuration. The runtime blocks
    /// caught signal delivery across reads/replacements, including callbacks
    /// interrupting sigaltstack itself. Atomics permit native fork snapshots.
    pub fn snapshot(&self, pointer: usize) -> Stack {
        let size = self.size.load(Ordering::Acquire);
        let base = self.base.load(Ordering::Relaxed);
        Stack {
            ss_sp: base,
            ss_size: size,
            ss_flags: if size == 0 {
                SS_DISABLE
            } else if pointer >= base && pointer - base < size {
                SS_ONSTACK
            } else {
                0
            },
        }
    }

    pub fn reset(&self) {
        self.size.store(0, Ordering::Release);
        self.base.store(0, Ordering::Relaxed);
    }

    pub fn replace(&self, requested: Stack, pointer: usize) -> Result<Stack, StackError> {
        let previous = self.snapshot(pointer);
        if previous.ss_flags == SS_ONSTACK {
            return Err(StackError::InUse);
        }
        match requested.ss_flags {
            SS_DISABLE => self.reset(),
            0 => {
                if requested.ss_size < MIN_SIZE {
                    return Err(StackError::TooSmall);
                }
                let end = requested
                    .ss_sp
                    .checked_add(requested.ss_size)
                    .ok_or(StackError::Range)?;
                if requested.ss_sp == 0 || end > 1_usize << 47 {
                    return Err(StackError::Range);
                }
                self.base.store(requested.ss_sp, Ordering::Relaxed);
                self.size.store(requested.ss_size, Ordering::Release);
            }
            _ => return Err(StackError::Flags),
        }
        Ok(previous)
    }

    /// Choose a stack before unblocking signals. Native callbacks execute on
    /// private runtime storage, so also inspect the actual interrupted RSP.
    /// Preserve the x86-64 red zone if that RSP already uses the alternate area.
    pub fn select(
        &self,
        current: usize,
        interrupted: usize,
        requested: bool,
        native: bool,
    ) -> Result<(Stack, Option<usize>), StackError> {
        let mut previous = self.snapshot(interrupted);
        let current_on_stack = self.snapshot(current).ss_flags == SS_ONSTACK;
        let interrupted_on_stack = previous.ss_flags == SS_ONSTACK;
        if current_on_stack {
            previous.ss_flags = SS_ONSTACK;
        }
        if current_on_stack {
            return Ok((previous, None));
        }
        if previous.ss_flags == SS_DISABLE || (!requested && !interrupted_on_stack) {
            // A native upcall's private runtime stack is never the ordinary
            // POSIX handler stack. Synchronous checkpoints already execute
            // in the app's live call chain and must not overlap those frames.
            let top = if native {
                Some(
                    interrupted
                        .checked_sub(128)
                        .filter(|top| *top >= 16)
                        .ok_or(StackError::Range)?
                        & !15,
                )
            } else {
                None
            };
            return Ok((previous, top));
        }
        let top = if interrupted_on_stack {
            interrupted.checked_sub(128).ok_or(StackError::TooSmall)?
        } else {
            previous.ss_sp + previous.ss_size
        } & !15;
        if top < previous.ss_sp + 16 {
            return Err(StackError::TooSmall);
        }
        Ok((previous, Some(top)))
    }
}

pub fn current_pointer() -> usize {
    let pointer;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) pointer, options(nomem, nostack, preserves_flags));
    }
    pointer
}

core::arch::global_asm!(include_str!("signal_stack_x86_64.S"));
unsafe extern "C" {
    fn mochios_posix_enter_on_stack(
        top: usize,
        callback: unsafe extern "C" fn(*mut c_void) -> !,
        argument: *mut c_void,
    ) -> !;
    fn mochios_posix_call_on_stack(
        top: usize,
        callback: unsafe extern "C" fn(*mut c_void),
        argument: *mut c_void,
    );
}

/// Calls a returning callback on caller-owned writable stack storage.
///
/// # Safety
/// The selected stack must be live, sufficiently large and disjoint from all
/// active frames. The callback must follow the C ABI and return normally; it
/// must not free either stack or retain pointers to expired stack frames.
pub unsafe fn call_on(
    top: usize,
    callback: unsafe extern "C" fn(*mut c_void),
    argument: *mut c_void,
) {
    unsafe { mochios_posix_call_on_stack(top, callback, argument) };
}

/// Enter a nonreturning callback on caller-owned writable storage.
///
/// # Safety
/// As with call_on, the selected region must be live, sufficiently large and
/// disjoint from all still-active frames. All old-stack cleanup must already
/// be finished. The callback must never return or read freed argument storage;
/// it must copy anything needed before releasing the previous stack.
pub unsafe fn enter_on(
    top: usize,
    callback: unsafe extern "C" fn(*mut c_void) -> !,
    argument: *mut c_void,
) -> ! {
    unsafe { mochios_posix_enter_on_stack(top, callback, argument) }
}
