//! Allocation-free ownership for runtime frames that a C callback can abandon.
//! Nodes are published only after pinning, and retired before their storage is
//! reclaimed. This is user-space bookkeeping, not a kernel object mechanism.
use core::{
    marker::PhantomPinned,
    pin::Pin,
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering},
};
use mochios_posix_client::upcall_guard::Guard;

#[repr(C)]
struct Link {
    previous: *mut Link,
    context: u64,
    active: bool,
    discard: unsafe fn(*mut Link),
}

pub(super) struct Chain {
    head: AtomicPtr<Link>,
    callback_defer: AtomicU32,
    pending: AtomicBool,
}

impl Chain {
    pub(super) const fn new() -> Self {
        Self {
            head: AtomicPtr::new(ptr::null_mut()),
            callback_defer: AtomicU32::new(0),
            pending: AtomicBool::new(false),
        }
    }
    pub(super) fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire).is_null()
    }

    /// Unlike native_delivery_defer, this delays application handlers only.
    /// Native upcalls must still run far enough to notify the pending wait.
    pub(super) fn defer_callbacks(&self) -> Option<Guard<'_>> {
        Guard::enter(&self.callback_defer)
    }

    pub(super) fn is_deferred(&self) -> bool {
        self.callback_defer.load(Ordering::Acquire) != 0
    }

    pub(super) fn notification_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }

    /// Called by the owning runtime's native upcall. True means notify the
    /// waiter but do NOT dequeue or invoke an application handler yet.
    pub(super) fn record_notification(&self) -> bool {
        if !self.is_deferred() {
            return false;
        }
        self.pending.store(true, Ordering::Release);
        true
    }

    /// Clear before querying/dispatching service-owned signals, never while
    /// application callbacks remain deferred. No signal payload is stored here.
    pub(super) fn take_notification(&self) -> bool {
        !self.is_deferred() && self.pending.swap(false, Ordering::AcqRel)
    }

    pub(super) fn reset_empty(&self) -> bool {
        if !self.is_empty() || self.is_deferred() {
            return false;
        }
        self.pending.store(false, Ordering::Release);
        true
    }

    /// Retire frames created in `context` or its nested callback contexts.
    /// The target callback's own pre-existing parent operations are preserved.
    ///
    /// # Safety
    /// Run on the owner thread with asynchronous callbacks deferred. All linked
    /// nodes must remain pinned and live. The caller must first validate the
    /// destination context and must NEVER return through selected frames. In
    /// particular, a tracked operation may invoke application code only in a
    /// nested callback context, not directly in its own creation context.
    pub(super) unsafe fn abandon_from(&self, context: u64) {
        loop {
            let pointer = self.head.load(Ordering::Acquire);
            if pointer.is_null() {
                return;
            }
            let (origin, previous, discard) = unsafe {
                let link = &*pointer;
                (link.context, link.previous, link.discard)
            };
            if origin < context {
                return;
            }
            self.head.store(previous, Ordering::Release);
            // Detach before invoking resource destructors. The discard routine
            // disarms the node, so it cannot release the same resource twice.
            unsafe { discard(pointer) };
        }
    }
}

#[repr(C)]
pub(super) struct Scope<'a, R> {
    // repr(C) and this first field are required by discard's private cast.
    link: Link,
    chain: &'a Chain,
    resource: Option<R>,
    _pinned: PhantomPinned,
}

impl<'a, R> Scope<'a, R> {
    pub(super) fn new(chain: &'a Chain, context: u64, resource: R) -> Self {
        Self {
            link: Link {
                previous: ptr::null_mut(),
                context,
                active: false,
                discard: discard::<R>,
            },
            chain,
            resource: Some(resource),
            _pinned: PhantomPinned,
        }
    }

    /// # Safety
    /// Only the chain's owning thread may publish nodes, with callbacks
    /// deferred until publication completes. The node must stay pinned until
    /// normal LIFO retirement or a non-returning abandonment transition.
    pub(super) unsafe fn activate(self: Pin<&mut Self>) {
        let scope = unsafe { self.get_unchecked_mut() };
        assert!(!scope.link.active, "runtime resource scope already active");
        assert!(
            scope.resource.is_some(),
            "runtime resource scope already retired"
        );
        scope.link.previous = scope.chain.head.load(Ordering::Acquire);
        if !scope.link.previous.is_null() {
            assert!(
                unsafe { (*scope.link.previous).context } <= scope.link.context,
                "runtime callback contexts must be nested"
            );
        }
        scope.link.active = true;
        scope.chain.head.store(&mut scope.link, Ordering::Release);
    }

    pub(super) fn resource(&self) -> Option<&R> {
        self.resource.as_ref()
    }
    pub(super) fn resource_mut(self: Pin<&mut Self>) -> Option<&mut R> {
        // R is not structurally pinned; only this node's link address is.
        unsafe { self.get_unchecked_mut() }.resource.as_mut()
    }

    /// # Safety
    /// Retire on the owning thread with callbacks deferred. This must be the
    /// top live scope. Resource destruction must finish before delivery reopens.
    pub(super) unsafe fn retire(self: Pin<&mut Self>) {
        let scope = unsafe { self.get_unchecked_mut() };
        scope.retire_inner();
    }

    fn retire_inner(&mut self) {
        if self.link.active {
            assert_eq!(
                self.chain.head.load(Ordering::Acquire),
                &mut self.link as *mut Link,
                "non-LIFO runtime resource retirement"
            );
            self.chain.head.store(self.link.previous, Ordering::Release);
            self.link.active = false;
        }
        drop(self.resource.take());
    }
}

impl<R> Drop for Scope<'_, R> {
    fn drop(&mut self) {
        // Callers explicitly retire under their delivery guard; inactive
        // nodes, including abandoned ones, have no resource left to release.
        // An unactivated construction may also be dropped normally.
        assert!(
            !self.link.active,
            "runtime resource scope must be retired under its delivery guard"
        );
    }
}

unsafe fn discard<R>(pointer: *mut Link) {
    let scope = unsafe { &mut *pointer.cast::<Scope<'_, R>>() };
    scope.link.active = false;
    drop(scope.resource.take());
}
