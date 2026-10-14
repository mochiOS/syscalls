use super::*;
use mochios_posix_client::{
    signal_context::{Stack, REG_RSP},
    signal_stack as stack,
};

fn error(error: stack::StackError) -> c_int {
    match error {
        stack::StackError::InUse => EPERM,
        stack::StackError::TooSmall => ENOMEM,
        stack::StackError::Flags | stack::StackError::Range => EINVAL,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigaltstack(requested: *const Stack, previous: *mut Stack) -> c_int {
    let result = (|| {
        let (_, control) = register_current_thread().ok_or(EAGAIN)?;
        let mask = service_signal_mask(control, posix_protocol::SIGNAL_MASK_BLOCK, u64::MAX)?;
        let changed = (|| {
            let pointer = stack::current_pointer();
            let old = if requested.is_null() {
                control.alternate_stack.snapshot(pointer)
            } else {
                control
                    .alternate_stack
                    .replace(unsafe { requested.read() }, pointer)
                    .map_err(error)?
            };
            if !previous.is_null() {
                unsafe { previous.write(old) };
            }
            Ok(0)
        })();
        service_signal_mask(control, posix_protocol::SIGNAL_MASK_SET, mask)?;
        changed
    })();
    result_with_errno(result, -1)
}

struct Invocation<'a> {
    control: &'a ThreadControl,
    action: SignalAction,
    signal: c_int,
    info: Option<&'a mut SigInfo>,
    context: &'a mut UContext,
    mask: u64,
    result: Result<(), c_int>,
    preparation: &'a mut Preparation,
    scope: core::pin::Pin<&'a mut signal_scope::Scope>,
}

unsafe extern "C" fn call(argument: *mut c_void) {
    let invocation = unsafe { &mut *argument.cast::<Invocation<'_>>() };
    match invocation
        .preparation
        .begin_with(|| invocation.scope.as_mut().activate())
    {
        Ok(true) => {}
        Ok(false) => return,
        Err(error) => {
            invocation.result = Err(error);
            return;
        }
    }
    // Unblock only after physically entering the selected stack. A nested
    // delivery will then see a valid interrupted RSP, never a half-switch.
    loop {
        let epoch = FORK_EPOCH.load(Ordering::Acquire);
        let restored = service_signal_mask(
            invocation.control,
            posix_protocol::SIGNAL_MASK_SET,
            invocation.mask,
        );
        // The handler frame has committed. If a nested handler forks while
        // unmasking, establish its mask in the child, not from a copied reply.
        if FORK_EPOCH.load(Ordering::Acquire) != epoch {
            continue;
        }
        invocation.result = restored.map(|_| ());
        break;
    }
    if invocation.result.is_err() {
        let _ = invocation.preparation.finish();
        return;
    }
    if let Some(info) = invocation.info.as_deref_mut() {
        let function: unsafe extern "C" fn(c_int, *mut SigInfo, *mut c_void) =
            unsafe { core::mem::transmute(invocation.action.handler) };
        unsafe {
            function(
                invocation.signal,
                info,
                (invocation.context as *mut UContext).cast(),
            )
        };
    } else {
        let function: unsafe extern "C" fn(c_int) =
            unsafe { core::mem::transmute(invocation.action.handler) };
        unsafe { function(invocation.signal) };
    }
    invocation.result = invocation.preparation.finish();
}

pub(super) fn invoke(
    control: &ThreadControl,
    action: SignalAction,
    signal: c_int,
    info: Option<&mut SigInfo>,
    context: &mut UContext,
    native: bool,
    preparation: &mut Preparation,
    scope: core::pin::Pin<&mut signal_scope::Scope>,
) -> Result<(), c_int> {
    // No mutex can be held by a thread interrupted by its own callback.
    // Mask shared POSIX state while selecting a coherent local configuration.
    let mask = service_signal_mask(control, posix_protocol::SIGNAL_MASK_BLOCK, u64::MAX)?;
    let selected = control.alternate_stack.select(
        stack::current_pointer(),
        context.uc_mcontext.gregs[REG_RSP] as usize,
        action.sa_flags & SA_ONSTACK != 0,
        native,
    );
    let (previous, top) = match selected {
        Ok(selected) => selected,
        Err(failure) => {
            service_signal_mask(control, posix_protocol::SIGNAL_MASK_SET, mask)?;
            return Err(error(failure));
        }
    };
    context.uc_stack = previous;
    let mut invocation = Invocation {
        control,
        action,
        signal,
        info,
        context,
        mask,
        result: Ok(()),
        preparation,
        scope,
    };
    let argument = (&mut invocation as *mut Invocation<'_>).cast();
    unsafe {
        if let Some(top) = top {
            stack::call_on(top, call, argument);
        } else {
            call(argument);
        }
    }
    invocation.result
}
