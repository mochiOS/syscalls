use super::*;
use mochios_posix_client::atfork::{Callback, Handlers, Registry};

static REGISTRY: RuntimeMutex<Registry> = RuntimeMutex::new(Registry::new());

pub(super) struct AllocatorGuard {
    _delivery: Option<mochios_posix_client::upcall_guard::Guard<'static>>,
}

pub(super) fn freeze_allocator() -> AllocatorGuard {
    let delivery = defer_native_delivery();
    __retarget_lock_acquire_recursive(ptr::from_ref(&__lock___malloc_recursive_mutex).cast_mut());
    AllocatorGuard {
        _delivery: delivery,
    }
}

impl Drop for AllocatorGuard {
    fn drop(&mut self) {
        __retarget_lock_release_recursive(
            ptr::from_ref(&__lock___malloc_recursive_mutex).cast_mut(),
        );
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_atfork(
    prepare: Option<Callback>,
    parent: Option<Callback>,
    child: Option<Callback>,
) -> c_int {
    let result = unsafe {
        REGISTRY.lock().register(
            Handlers {
                prepare,
                parent,
                child,
            },
            |layout| malloc(layout.size()).cast::<u8>(),
        )
    };
    if result.is_ok() { 0 } else { ENOMEM }
}

pub(super) fn run(fork: impl FnOnce() -> Result<c_int, c_int>) -> Result<c_int, c_int> {
    let handlers = REGISTRY.lock().snapshot();
    unsafe { handlers.prepare() };
    // Keep registration out of the clone point, so the child cannot inherit
    // this registry locked by a vanished thread. No handler runs under it.
    let guard = REGISTRY.lock();
    let result = fork();
    drop(guard);
    if matches!(result, Ok(0)) {
        unsafe { handlers.child() };
    } else {
        unsafe { handlers.parent() };
    }
    result
}
