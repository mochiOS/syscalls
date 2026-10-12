use core::ffi::{c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

pub type Routine = unsafe extern "C" fn(*mut c_void);

/// Matches newlib's stack-allocated struct _pthread_cleanup_context.
#[repr(C)]
pub struct Context {
    routine: Option<Routine>,
    argument: *mut c_void,
    cancel_type: c_int,
    previous: *mut Context,
}

/// Safety: head belongs exclusively to the calling thread; context is a
/// writable SDK context which stays live until its matching pop or thread exit.
pub unsafe fn push(
    head: &AtomicUsize,
    context: *mut Context,
    routine: Option<Routine>,
    argument: *mut c_void,
    cancel_type: c_int,
) {
    unsafe {
        context.write(Context {
            routine,
            argument,
            cancel_type,
            previous: head.load(Ordering::Acquire) as *mut Context,
        });
    }
    head.store(context as usize, Ordering::Release);
}

/// Safety: head is thread-owned and all linked SDK contexts remain live. Pop
/// must name its current top. Detach before invoking application code so nested
/// push/pop or a cancellation point cannot execute the same handler twice.
pub unsafe fn pop(head: &AtomicUsize, context: *mut Context, execute: bool) -> Option<c_int> {
    if context.is_null() || head.load(Ordering::Acquire) != context as usize {
        return None;
    }
    let context = unsafe { &mut *context };
    let routine = context.routine;
    let argument = context.argument;
    let cancel_type = context.cancel_type;
    head.store(context.previous as usize, Ordering::Release);
    context.previous = ptr::null_mut();
    if execute {
        if let Some(routine) = routine {
            unsafe { routine(argument) };
        }
    }
    Some(cancel_type)
}

/// Safety: all linked contexts belong to this thread and their stack frames
/// are still live; callers disable cancellation before exit cleanup.
pub unsafe fn drain(head: &AtomicUsize) {
    loop {
        let context = head.load(Ordering::Acquire) as *mut Context;
        if context.is_null() {
            return;
        }
        let _ = unsafe { pop(head, context, true) };
    }
}
