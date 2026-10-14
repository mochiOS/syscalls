use super::*;
use mochios_posix_client::upcall_guard::Guard;

const MAGIC: u64 = 0x6d6f_6368_736a_6d70;

#[repr(C)]
#[derive(Clone, Copy)]
struct JumpBuffer {
    registers: [u64; 8], // rbx rbp r12 r13 r14 r15 rsp rip
    mask: u64,
    thread: u64,
    scope: u64,
    native: u64,
    save_mask: u64,
    defer_depth: u64,
    magic: u64,
}

const _: () = {
    assert!(core::mem::size_of::<JumpBuffer>() == 120);
    assert!(core::mem::offset_of!(JumpBuffer, mask) == 64);
    assert!(core::mem::offset_of!(JumpBuffer, magic) == 112);
};

core::arch::global_asm!(include_str!("signal_jump_x86_64.S"));
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
        core::arch::asm!("fxsave64 [{}]", in(reg) saved.fx_state.as_mut_ptr(), options(nostack));
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
            saved.registers.rsi = value as u64;
            saved.registers.rdx = defer as u64;
            saved.registers.rcx = u64::from(depth);
        }
        NativeDestination::Cleanup { transition } => {
            saved.instruction = finish_jump as *const () as u64;
            saved.argument = transition as u64;
            unsafe {
                ((top - 8) as *mut u64).write(0);
            }
        }
    }
    saved.stack_pointer = (top - 8) as u64;
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
            || buffer.registers[6] < 144
            || buffer.registers[6] >> 47 != 0
            || buffer.registers[7] == 0
            || buffer.registers[7] >> 47 != 0
        {
            return Err(EINVAL);
        }
        let guard = Guard::enter(&control.native_delivery_defer).ok_or(EOVERFLOW)?;
        unsafe { signal_scope::validate_target(control, buffer.scope) }?;
        let owner = native_process_id().map_err(|error| map_kernel_errno(error.raw()))?;
        let top = (buffer.registers[6] as usize - 128) & !15;
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
            core::mem::forget(guard);
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
        // No Rust-owned resource may survive the jump. The assembly reopens
        // delivery only after restoring the destination RSP and all saved data.
        core::mem::forget(guard);
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
