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
struct Mapping {
    base: usize,
    size: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Transition {
    buffer: JumpBuffer,
    value: c_int,
    depth: u32,
    defer: *const AtomicU32,
    mapping_size: usize,
    count: usize,
}

unsafe extern "C" fn finish_jump(argument: *mut c_void) -> ! {
    // We are on the destination stack, below its red zone. Copy all jump data
    // before freeing either orphan callback storage or the staging mapping.
    let task = unsafe { argument.cast::<Transition>().read_volatile() };
    let mappings = unsafe {
        argument
            .cast::<u8>()
            .add(core::mem::size_of::<Transition>())
            .cast::<Mapping>()
    };
    for index in 0..task.count {
        let mapping = unsafe { mappings.add(index).read() };
        if syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryUnmap,
            mapping.base as u64,
            mapping.size as u64,
        ))
        .is_err()
        {
            process_exit(127);
        }
    }
    if syscall_errno(syscall::raw_syscall2(
        syscall::SyscallNumber::MemoryUnmap,
        argument as u64,
        task.mapping_size as u64,
    ))
    .is_err()
    {
        process_exit(127);
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
        workspace: usize,
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
        NativeDestination::Cleanup { workspace } => {
            saved.instruction = finish_jump as *const () as u64;
            saved.argument = workspace as u64;
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
        let mut count = 0usize;
        let mut token = None;
        unsafe {
            signal_delivery::visit_abandoned(control, buffer.native, |frame| {
                if frame.owner == owner {
                    if token.replace(frame.token).is_some() {
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
                    count = count.checked_add(1).ok_or(EOVERFLOW)?;
                }
                Ok(())
            })
        }?;
        if count == 0 {
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
        let size = count
            .checked_mul(core::mem::size_of::<Mapping>())
            .and_then(|bytes| bytes.checked_add(core::mem::size_of::<Transition>()))
            .and_then(|bytes| align_up(bytes, PAGE_SIZE))
            .ok_or(EOVERFLOW)?;
        // Direct anonymous VM: no malloc/stdio lock, and no fixed ancestry cap.
        let workspace = syscall_errno(syscall::raw_syscall6(
            syscall::SyscallNumber::MemoryMap,
            0,
            size as u64,
            NATIVE_READ_WRITE,
            0,
            0,
            0,
        ))? as usize;
        let mappings = (workspace + core::mem::size_of::<Transition>()) as *mut Mapping;
        let mut index = 0;
        unsafe {
            signal_delivery::visit_abandoned(control, buffer.native, |frame| {
                if frame.owner != owner {
                    if index >= count {
                        return Err(EINVAL);
                    }
                    mappings.add(index).write(Mapping {
                        base: frame.stack,
                        size: frame.size,
                    });
                    index += 1;
                }
                Ok(())
            })
        }?;
        if index != count {
            return Err(EINVAL);
        }
        unsafe {
            (workspace as *mut Transition).write(Transition {
                buffer,
                value,
                depth: buffer.defer_depth as u32,
                defer: &control.native_delivery_defer,
                mapping_size: size,
                count,
            });
        }
        unsafe { prepare_jump(control, &buffer) }?;
        // No Rust-owned resource may survive the jump. The assembly reopens
        // delivery only after restoring the destination RSP and all saved data.
        core::mem::forget(guard);
        if let Some(token) = token {
            leave_native(token, top, NativeDestination::Cleanup { workspace });
        }
        unsafe {
            mochios_posix_client::signal_stack::enter_on(top, finish_jump, workspace as *mut c_void)
        }
    })();
    match result {
        Err(error) => process_exit(error),
        Ok(never) => never,
    }
}
