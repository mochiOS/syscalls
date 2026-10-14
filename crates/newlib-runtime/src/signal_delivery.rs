use super::*;
use core::{
    marker::{PhantomData, PhantomPinned},
    pin::Pin,
};
use mochios_posix_client::signal_context::{MachineContext, Stack};

/// A native callback's runtime frames remain live across a userspace VM clone.
/// The child has its own native thread, so neither its return token nor the
/// parent's service delivery is inherited. This link tracks storage, not token
/// authority, and is only read/written by the current thread.
pub(super) struct NativeFrame {
    control: &'static ThreadControl,
    owner: u64,
    token: u64,
    id: u64,
    previous: usize,
    previous_id: u64,
    stack: usize,
    size: usize,
    active: bool,
    retired: bool,
    _pin: PhantomPinned,
    _thread_bound: PhantomData<*mut ()>,
}

impl NativeFrame {
    pub(super) fn new(token: u64) -> Result<Self, c_int> {
        if token == 0 {
            return Err(EINVAL);
        }
        let (_, control) = current_thread_control().ok_or(EAGAIN)?;
        let mut id = control.next_native_signal_frame_id.load(Ordering::Relaxed);
        loop {
            let next = id.checked_add(1).ok_or(EOVERFLOW)?;
            match control.next_native_signal_frame_id.compare_exchange_weak(
                id,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => id = current,
            }
        }
        Ok(Self {
            control,
            owner: native_process_id().map_err(|error| map_kernel_errno(error.raw()))?,
            token,
            id,
            previous: 0,
            previous_id: 0,
            stack: control.signal_upcall_stack.load(Ordering::Acquire),
            size: control.signal_upcall_stack_size.load(Ordering::Acquire),
            active: false,
            retired: false,
            _pin: PhantomPinned,
            _thread_bound: PhantomData,
        })
    }

    pub(super) fn activate(self: Pin<&mut Self>) -> Result<(), c_int> {
        // Publishing a stack address requires that it remain fixed until the
        // frame is retired. Only the current thread may mutate this chain.
        let frame = unsafe { self.get_unchecked_mut() };
        let _guard =
            mochios_posix_client::upcall_guard::Guard::enter(&frame.control.native_delivery_defer)
                .ok_or(EOVERFLOW)?;
        if frame.active || frame.retired {
            return Err(EINVAL);
        }
        frame.previous = frame
            .control
            .active_native_signal_frame
            .load(Ordering::Acquire);
        frame.previous_id = frame
            .control
            .active_native_signal_frame_id
            .load(Ordering::Acquire);
        frame.active = true;
        frame
            .control
            .active_native_signal_frame_id
            .store(frame.id, Ordering::Relaxed);
        frame
            .control
            .active_native_signal_frame
            .store(frame as *mut Self as usize, Ordering::Release);
        Ok(())
    }

    fn deactivate(self: Pin<&mut Self>) -> Result<(), c_int> {
        let frame = unsafe { self.get_unchecked_mut() };
        let _guard =
            mochios_posix_client::upcall_guard::Guard::enter(&frame.control.native_delivery_defer)
                .ok_or(EOVERFLOW)?;
        if !frame.active
            || frame
                .control
                .active_native_signal_frame
                .load(Ordering::Acquire)
                != frame as *mut Self as usize
            || frame
                .control
                .active_native_signal_frame_id
                .load(Ordering::Acquire)
                != frame.id
        {
            return Err(EINVAL);
        }
        frame.active = false;
        frame.retired = true;
        frame
            .control
            .active_native_signal_frame_id
            .store(frame.previous_id, Ordering::Relaxed);
        frame
            .control
            .active_native_signal_frame
            .store(frame.previous, Ordering::Release);
        Ok(())
    }
}

pub(super) fn stack_is_active(control: &ThreadControl, base: usize, size: usize) -> bool {
    let frame = control.active_native_signal_frame.load(Ordering::Acquire);
    frame >= base && frame - base < size
}

/// Local storage/return metadata, never a grant of authority over another
/// thread. In a fork child, `owner` differs and `token` must not be returned.
#[derive(Clone, Copy)]
pub(super) struct AbandonedFrame {
    pub(super) owner: u64,
    pub(super) token: u64,
    pub(super) stack: usize,
    pub(super) size: usize,
}

unsafe fn walk_to(
    control: &ThreadControl,
    target: u64,
    mut visit: impl FnMut(AbandonedFrame) -> Result<(), c_int>,
) -> Result<(), c_int> {
    if control.native_delivery_defer.load(Ordering::Acquire) == 0 {
        return Err(EINVAL);
    }
    let mut pointer = control.active_native_signal_frame.load(Ordering::Acquire);
    let mut id = control
        .active_native_signal_frame_id
        .load(Ordering::Acquire);
    loop {
        if pointer == 0 {
            return if id == 0 && target == 0 {
                Ok(())
            } else {
                Err(EINVAL)
            };
        }
        let frame = unsafe { &*(pointer as *const NativeFrame) };
        if id == 0
            || frame.id != id
            || !frame.active
            || frame.retired
            || !core::ptr::eq(frame.control, control)
            || frame.previous_id >= id
            || (frame.previous == 0) != (frame.previous_id == 0)
        {
            return Err(EINVAL);
        }
        if id == target {
            return Ok(());
        }
        visit(AbandonedFrame {
            owner: frame.owner,
            token: frame.token,
            stack: frame.stack,
            size: frame.size,
        })?;
        pointer = frame.previous;
        id = frame.previous_id;
    }
}

/// Stage the metadata needed to leave native callbacks during a nonlocal jump.
/// The destination is validated before the visitor is called even once.
///
/// # Safety
/// Only the owning thread may call this, with its native delivery guard held.
/// Its published records must remain pinned and live. The visitor must not
/// alter that chain or execute a user callback. It must stage metadata only:
/// no recorded stack may be unmapped while execution can still use it.
pub(super) unsafe fn visit_abandoned(
    control: &ThreadControl,
    target: u64,
    visit: impl FnMut(AbandonedFrame) -> Result<(), c_int>,
) -> Result<(), c_int> {
    unsafe { walk_to(control, target, |_| Ok(())) }?;
    unsafe { walk_to(control, target, visit) }
}

/// Unlink only callbacks inside the saved destination. This does not consume
/// a kernel return token, restore CPU state or free any stack mapping.
///
/// # Safety
/// The requirements of `visit_abandoned` apply. The caller must first retain
/// any required return/storage metadata and must not return through retired
/// callback frames. Keep delivery deferred until the actual stack transition;
/// removing a local record alone does not end an active native upcall.
pub(super) unsafe fn retire_to(control: &ThreadControl, target: u64) -> Result<(), c_int> {
    unsafe { walk_to(control, target, |_| Ok(())) }?;
    while control
        .active_native_signal_frame_id
        .load(Ordering::Acquire)
        != target
    {
        let pointer = control.active_native_signal_frame.load(Ordering::Acquire);
        let frame = unsafe { Pin::new_unchecked(&mut *(pointer as *mut NativeFrame)) };
        frame.deactivate()?;
    }
    Ok(())
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

pub(super) fn resume(context: &UContext, mut frame: Pin<&mut NativeFrame>) -> ! {
    let saved = context.native_snapshot();
    let owner = native_process_id().unwrap_or_else(|_| process_exit(127));
    frame
        .as_mut()
        .deactivate()
        .unwrap_or_else(|error| process_exit(error));
    let frame = frame.as_ref().get_ref();
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
        frame.token,
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
