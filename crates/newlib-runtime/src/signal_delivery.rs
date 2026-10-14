use super::*;
use mochios_posix_client::signal_context::{MachineContext, Stack};

/// A native callback's runtime frames remain live across a userspace VM clone.
/// The child has its own native thread, so neither its return token nor the
/// parent's service delivery is inherited. This link tracks storage, not token
/// authority, and is only read/written by the current thread.
pub(super) struct NativeFrame {
    control: &'static ThreadControl,
    owner: u64,
    previous: usize,
    stack: usize,
    size: usize,
}

impl NativeFrame {
    pub(super) fn new() -> Result<Self, c_int> {
        let (_, control) = current_thread_control().ok_or(EAGAIN)?;
        Ok(Self {
            control,
            owner: native_process_id().map_err(|error| map_kernel_errno(error.raw()))?,
            previous: control.active_native_signal_frame.load(Ordering::Acquire),
            stack: control.signal_upcall_stack.load(Ordering::Acquire),
            size: control.signal_upcall_stack_size.load(Ordering::Acquire),
        })
    }

    pub(super) fn activate(&mut self) {
        self.control
            .active_native_signal_frame
            .store(self as *mut Self as usize, Ordering::Release);
    }
}

pub(super) fn stack_is_active(control: &ThreadControl, base: usize, size: usize) -> bool {
    let frame = control.active_native_signal_frame.load(Ordering::Acquire);
    frame >= base && frame - base < size
}

fn context(machine: MachineContext) -> UContext {
    UContext {
        uc_flags: 0,
        uc_link: 0,
        uc_sigmask: 0, // Set to the authoritative pre-handler mask by dispatch.
        // The native upcall stack is private runtime storage, not sigaltstack.
        uc_stack: Stack {
            ss_sp: 0,
            ss_flags: 2,
            ss_size: 0,
        },
        uc_mcontext: machine,
    }
}

pub(super) fn drain() -> Result<(), c_int> {
    if current_thread_control()
        .is_some_and(|(_, control)| control.native_delivery_defer.load(Ordering::Acquire) != 0)
    {
        return Ok(());
    }
    unsafe extern "C" fn deliver(machine: *mut MachineContext, result: *mut c_void) {
        let mut frame = context(unsafe { machine.read() });
        let delivered = drain_pending_signals_with_context(&mut frame, false);
        unsafe {
            if delivered.is_ok() {
                machine.write(frame.uc_mcontext);
            }
            result.cast::<Result<(), c_int>>().write(delivered);
        }
    }
    let mut result = Ok(());
    unsafe {
        mochios_posix_client::signal_checkpoint::run_with(
            deliver,
            (&mut result as *mut Result<(), c_int>).cast(),
        );
    }
    result
}

pub(super) fn interrupted(token: u64) -> Result<UContext, c_int> {
    let mut saved = MaybeUninit::<mnu_abi::ThreadUpcallSnapshot>::uninit();
    syscall_errno(syscall::raw_syscall3(
        syscall::SyscallNumber::ThreadUpcallInspect,
        token,
        saved.as_mut_ptr() as u64,
        core::mem::size_of::<mnu_abi::ThreadUpcallSnapshot>() as u64,
    ))?;
    let saved = unsafe { saved.assume_init() };
    let frame = UContext::from_native(
        &saved,
        0,
        Stack {
            ss_sp: 0,
            ss_flags: 2,
            ss_size: 0,
        },
    );
    Ok(frame)
}

#[derive(Clone, Copy)]
struct DetachedReturn {
    saved: mnu_abi::ThreadUpcallSnapshot,
    stack: usize,
    size: usize,
}

unsafe extern "C" fn finish_detached(argument: *mut c_void) -> ! {
    // Materialize the whole record on the destination stack before unmapping
    // its old source. This callback never returns through the retired frames.
    let detached = unsafe { argument.cast::<DetachedReturn>().read_volatile() };
    if syscall_errno(syscall::raw_syscall2(
        syscall::SyscallNumber::MemoryUnmap,
        detached.stack as u64,
        detached.size as u64,
    ))
    .is_err()
    {
        process_exit(127);
    }
    let result = syscall::raw_syscall2(
        syscall::SyscallNumber::ThreadContextRestore,
        (&detached.saved as *const mnu_abi::ThreadUpcallSnapshot) as u64,
        core::mem::size_of::<mnu_abi::ThreadUpcallSnapshot>() as u64,
    );
    failed_resume(result)
}

pub(super) fn resume(token: u64, context: &UContext, frame: &NativeFrame) -> ! {
    let saved = context.native_snapshot();
    let owner = native_process_id().unwrap_or_else(|_| process_exit(127));
    frame
        .control
        .active_native_signal_frame
        .store(frame.previous, Ordering::Release);
    if owner != frame.owner {
        let top = (saved.stack_pointer as usize)
            .checked_sub(128)
            .filter(|top| *top >= 16)
            .unwrap_or_else(|| process_exit(EINVAL))
            & !15;
        if top >= frame.stack && top - frame.stack < frame.size {
            process_exit(EINVAL);
        }
        let mut detached = DetachedReturn {
            saved,
            stack: frame.stack,
            size: frame.size,
        };
        // All handler dispatch, service completion decisions and Rust cleanup
        // have finished. Scratch below the interrupted red zone is now free;
        // do not use the newly installed upcall stack as temporary storage.
        unsafe {
            mochios_posix_client::signal_stack::enter_on(
                top,
                finish_detached,
                (&mut detached as *mut DetachedReturn).cast(),
            );
        }
    }
    let result = syscall::raw_syscall3(
        syscall::SyscallNumber::ThreadUpcallReturnContext,
        token,
        (&saved as *const mnu_abi::ThreadUpcallSnapshot) as u64,
        core::mem::size_of::<mnu_abi::ThreadUpcallSnapshot>() as u64,
    );
    failed_resume(result)
}

fn failed_resume(result: syscall::RawSyscallResult) -> ! {
    let error = result.raw() as i64;
    process_exit(if error < 0 {
        map_kernel_errno(error)
    } else {
        127
    })
}
