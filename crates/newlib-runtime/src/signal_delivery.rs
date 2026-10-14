use super::*;
use mochios_posix_client::signal_context::{MachineContext, Stack};

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
    unsafe extern "C" fn deliver(machine: *mut MachineContext, result: *mut c_void) {
        let mut frame = context(unsafe { machine.read() });
        let delivered = drain_pending_signals_with_context(&mut frame);
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

pub(super) fn resume(token: u64, context: &UContext) -> ! {
    let saved = context.native_snapshot();
    let result = syscall::raw_syscall3(
        syscall::SyscallNumber::ThreadUpcallReturnContext,
        token,
        (&saved as *const mnu_abi::ThreadUpcallSnapshot) as u64,
        core::mem::size_of::<mnu_abi::ThreadUpcallSnapshot>() as u64,
    );
    let error = result.raw() as i64;
    process_exit(if error < 0 {
        map_kernel_errno(error)
    } else {
        127
    })
}
