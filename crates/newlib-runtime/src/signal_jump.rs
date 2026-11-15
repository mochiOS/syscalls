use super::*;
use mochios_posix_client::upcall_guard::Guard;

const MAGIC: u64 = 0x6d6f_6368_736a_6d70;
#[cfg(target_arch = "x86_64")]
const REGISTER_WORDS: usize = 8;
#[cfg(target_arch = "aarch64")]
const REGISTER_WORDS: usize = 21;
const RED_ZONE: usize = if cfg!(target_arch = "x86_64") { 128 } else { 0 };

#[repr(C)]
#[derive(Clone, Copy)]
struct JumpBuffer {
    // x86: RBX/RBP/R12..R15/SP/PC. ARM: X19..X30/SP/D8..D15.
    registers: [u64; REGISTER_WORDS],
    mask: u64,
    thread: u64,
    scope: u64,
    native: u64,
    save_mask: u64,
    defer_depth: u64,
    magic: u64,
}

const _: () = {
    assert!(core::mem::size_of::<JumpBuffer>() == (REGISTER_WORDS + 7) * 8);
    assert!(core::mem::offset_of!(JumpBuffer, mask) == REGISTER_WORDS * 8);
    assert!(core::mem::offset_of!(JumpBuffer, magic) == (REGISTER_WORDS + 6) * 8);
};

impl JumpBuffer {
    fn stack(&self) -> usize {
        self.registers[if cfg!(target_arch = "x86_64") { 6 } else { 12 }] as usize
    }
    fn instruction(&self) -> u64 {
        self.registers[if cfg!(target_arch = "x86_64") { 7 } else { 11 }]
    }
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("signal_jump_x86_64.S"));
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(include_str!("signal_jump_aarch64.S"));
unsafe extern "C" {
    fn __mochios_sigjump_restore(
        buffer: *const JumpBuffer,
        value: c_int,
        defer: *const AtomicU32,
        depth: u32,
    ) -> !;
}

#[unsafe(no_mangle)]
unsafe extern "C" fn __mochios_sigsetjmp_prepare(buffer: *mut JumpBuffer, save_mask: c_int) {
    let result = (|| {
        let (thread, control) = register_current_thread().ok_or(EAGAIN)?;
        let _guard = Guard::enter(&control.native_delivery_defer).ok_or(EOVERFLOW)?;
        let mask = if save_mask != 0 {
            service_signal_mask(control, posix_protocol::SIGNAL_MASK_QUERY, 0)?
        } else {
            0
        };
        // Assembly has already saved the caller's real callee-saved registers.
        // There is no PID in this identity: valid buffers survive native fork.
        unsafe {
            (*buffer).mask = mask;
            (*buffer).thread = u64::from(thread);
            (*buffer).scope = control.active_signal_scope_id.load(Ordering::Acquire);
            (*buffer).native = control
                .active_native_signal_frame_id
                .load(Ordering::Acquire);
            (*buffer).save_mask = u64::from(save_mask != 0);
            (*buffer).defer_depth =
                u64::from(control.native_delivery_defer.load(Ordering::Acquire) - 1);
            (*buffer).magic = MAGIC;
        }
        Ok::<(), c_int>(())
    })();
    result.unwrap_or_else(|error| process_exit(error));
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Transition {
    buffer: JumpBuffer,
    value: c_int,
    depth: u32,
    defer: *const AtomicU32,
    chain: signal_delivery::RetiredChain,
}

unsafe extern "C" fn finish_jump(argument: *mut c_void) -> ! {
    // We are on the destination stack, below its red zone. Copy all jump data
    // before freeing its host record. No allocation is needed even when fork
    // has left an arbitrarily long ancestry of private callback stacks.
    let mut task = unsafe { argument.cast::<Transition>().read_volatile() };
    loop {
        let frame = unsafe { task.chain.next() }.unwrap_or_else(|error| process_exit(error));
        let Some(frame) = frame else {
            break;
        };
        if syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryUnmap,
            frame.stack as u64,
            frame.size as u64,
        ))
        .is_err()
        {
            process_exit(127);
        }
    }
    unsafe { __mochios_sigjump_restore(&task.buffer, task.value, task.defer, task.depth) }
}

enum NativeDestination<'a> {
    Direct {
        buffer: &'a JumpBuffer,
        value: c_int,
        defer: *const AtomicU32,
        depth: u32,
    },
    Cleanup {
        transition: *mut Transition,
    },
}

#[inline(never)]
fn leave_native(token: u64, top: usize, destination: NativeDestination<'_>) -> ! {
    let mut saved = MaybeUninit::<mnu_abi::ThreadUpcallSnapshot>::uninit();
    syscall_errno(syscall::raw_syscall3(
        syscall::SyscallNumber::ThreadUpcallInspect,
        token,
        saved.as_mut_ptr() as u64,
        core::mem::size_of::<mnu_abi::ThreadUpcallSnapshot>() as u64,
    ))
    .unwrap_or_else(|error| process_exit(error));
    let mut saved = unsafe { saved.assume_init() };
    // longjmp does not restore a saved floating-point environment. Preserve
    // the jump caller's current one rather than the pre-handler FXSAVE image.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("fxsave64 [{}]", in(reg) saved.fx_state.as_mut_ptr(), options(nostack));
        #[cfg(target_arch = "aarch64")]
        {
            core::arch::asm!(
                "stp q0, q1, [{base}, #0]", "stp q2, q3, [{base}, #32]",
                "stp q4, q5, [{base}, #64]", "stp q6, q7, [{base}, #96]",
                "stp q8, q9, [{base}, #128]", "stp q10, q11, [{base}, #160]",
                "stp q12, q13, [{base}, #192]", "stp q14, q15, [{base}, #224]",
                "stp q16, q17, [{base}, #256]", "stp q18, q19, [{base}, #288]",
                "stp q20, q21, [{base}, #320]", "stp q22, q23, [{base}, #352]",
                "stp q24, q25, [{base}, #384]", "stp q26, q27, [{base}, #416]",
                "stp q28, q29, [{base}, #448]", "stp q30, q31, [{base}, #480]",
                "mrs {fpcr}, fpcr", "mrs {fpsr}, fpsr",
                base = in(reg) saved.fp_state.as_mut_ptr(),
                fpcr = out(reg) saved.fpcr, fpsr = out(reg) saved.fpsr,
                options(nostack, preserves_flags),
            );
        }
    }
    match destination {
        NativeDestination::Direct {
            buffer,
            value,
            defer,
            depth,
        } => {
            // The destination is naked assembly: it reads the old, still
            // mapped buffer before changing RSP, and never pushes to scratch.
            saved.instruction = __mochios_sigjump_restore as *const () as u64;
            saved.argument = buffer as *const JumpBuffer as u64;
            #[cfg(target_arch = "x86_64")]
            {
                saved.registers.rsi = value as u64;
                saved.registers.rdx = defer as u64;
                saved.registers.rcx = u64::from(depth);
            }
            #[cfg(target_arch = "aarch64")]
            {
                saved.registers.x[0] = value as u64;
                saved.registers.x[1] = defer as u64;
                saved.registers.x[2] = u64::from(depth);
            }
        }
        NativeDestination::Cleanup { transition } => {
            saved.instruction = finish_jump as *const () as u64;
            saved.argument = transition as u64;
            #[cfg(target_arch = "x86_64")]
            unsafe {
                ((top - 8) as *mut u64).write(0);
            }
            #[cfg(target_arch = "aarch64")]
            {
                saved.registers.x[29] = 0;
            }
        }
    }
    saved.stack_pointer = (top - if cfg!(target_arch = "x86_64") { 8 } else { 0 }) as u64;
    let result = syscall::raw_syscall3(
        syscall::SyscallNumber::ThreadUpcallReturnContext,
        token,
        (&saved as *const mnu_abi::ThreadUpcallSnapshot) as u64,
        core::mem::size_of::<mnu_abi::ThreadUpcallSnapshot>() as u64,
    );
    process_exit(syscall_errno(result).err().unwrap_or(127));
}

unsafe fn prepare_jump(control: &ThreadControl, buffer: &JumpBuffer) -> Result<(), c_int> {
    // Both callers retain their delivery guard through the final transition.
    unsafe { signal_scope::unwind_to(control, buffer.scope) }?;
    // The destination was validated before touching runtime ownership. The
    // calling transition keeps native delivery deferred through final restore.
    unsafe { control.callback_resources.abandon_from(buffer.scope) };
    if buffer.save_mask != 0 {
        service_signal_mask(control, posix_protocol::SIGNAL_MASK_SET, buffer.mask)?;
    }
    unsafe { signal_delivery::retire_to(control, buffer.native) }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn siglongjmp(buffer: *const JumpBuffer, value: c_int) -> ! {
    let result = (|| {
        // Invalid/expired C jump environments are undefined by POSIX. Still
        // fail closed for wrong-thread or no-longer-live handler identities.
        let buffer = unsafe { buffer.read() };
        let (thread, control) = current_thread_control().ok_or(EAGAIN)?;
        if buffer.magic != MAGIC
            || buffer.thread != u64::from(thread)
            || buffer.save_mask > 1
            || buffer.defer_depth >= u32::MAX as u64
            || buffer.stack() < RED_ZONE + 16
            || buffer.stack() >> 47 != 0
            || buffer.instruction() == 0
            || buffer.instruction() >> 47 != 0
            || (cfg!(target_arch = "aarch64")
                && (buffer.stack() & 15 != 0 || buffer.instruction() & 3 != 0))
        {
            return Err(EINVAL);
        }
        let guard = Guard::enter(&control.native_delivery_defer).ok_or(EOVERFLOW)?;
        // This function cannot return. Transfer responsibility for reopening
        // delivery to the final assembly before any fallible bookkeeping.
        // An error must keep callbacks deferred until process_exit, even when
        // a service completion has already consumed part of the old chain.
        core::mem::forget(guard);
        unsafe { signal_scope::validate_target(control, buffer.scope) }?;
        let owner = native_process_id().map_err(|error| map_kernel_errno(error.raw()))?;
        let top = (buffer.stack() - RED_ZONE) & !15;
        let mut has_orphans = false;
        let mut token = None;
        unsafe {
            signal_delivery::visit_abandoned(control, buffer.native, |frame| {
                if frame.owner == owner {
                    if token.replace(frame.token).is_some() || has_orphans {
                        return Err(EINVAL);
                    }
                } else {
                    if frame.stack == 0
                        || frame.size == 0
                        || (top >= frame.stack && top - frame.stack < frame.size)
                        || frame.stack == control.signal_upcall_stack.load(Ordering::Acquire)
                    {
                        return Err(EINVAL);
                    }
                    has_orphans = true;
                }
                Ok(())
            })
        }?;
        if !has_orphans {
            // Ordinary jumps (including native handler escape) cannot depend
            // on allocation succeeding. No orphan mapping needs reclamation.
            unsafe { prepare_jump(control, &buffer) }?;
            let defer = &control.native_delivery_defer;
            let depth = buffer.defer_depth as u32;
            if let Some(token) = token {
                leave_native(
                    token,
                    top,
                    NativeDestination::Direct {
                        buffer: &buffer,
                        value,
                        defer,
                        depth,
                    },
                );
            }
            unsafe { __mochios_sigjump_restore(&buffer, value, defer, depth) }
        }
        let transition = unsafe {
            signal_delivery::stage_jump(control, buffer.native, owner, |chain| Transition {
                buffer,
                value,
                depth: buffer.defer_depth as u32,
                defer: &control.native_delivery_defer,
                chain,
            })
        }?;
        unsafe { prepare_jump(control, &buffer) }?;
        if let Some(token) = token {
            leave_native(token, top, NativeDestination::Cleanup { transition });
        }
        unsafe { mochios_posix_client::signal_stack::enter_on(top, finish_jump, transition.cast()) }
    })();
    match result {
        Err(error) => process_exit(error),
        Ok(never) => never,
    }
}
