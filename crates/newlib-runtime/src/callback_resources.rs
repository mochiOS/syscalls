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

const FROZEN: u32 = 1 << 31;
const WAITING: u32 = 1 << 30;

/// Held during construction/publication or destruction, not across I/O waits.
struct Preparation<'a>(&'a Chain);
impl Drop for Preparation<'_> {
    fn drop(&mut self) {
        self.0.mutations.fetch_sub(1, Ordering::Release);
    }
}

pub(super) struct Capture<'a>(&'a Chain);
impl Drop for Capture<'_> {
    fn drop(&mut self) {
        if self.0.mutations.swap(0, Ordering::Release) & WAITING != 0 {
            (self.0.wake)(&self.0.mutations);
        }
    }
}

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
    mutations: AtomicU32,
    blockers: AtomicU32,
    wait: fn(&AtomicU32, u32),
    wake: fn(&AtomicU32),
}

impl Chain {
    #[cfg(not(target_os = "mochios"))]
    pub(super) const fn new() -> Self {
        // Host ownership fixtures do not freeze concurrently. A concurrent
        // fixture must explicitly supply its controlled wait transport.
        Self::with_wait(
            |_, _| panic!("resource wait transport not configured"),
            |_| {},
        )
    }

    pub(super) const fn with_wait(wait: fn(&AtomicU32, u32), wake: fn(&AtomicU32)) -> Self {
        Self {
            head: AtomicPtr::new(ptr::null_mut()),
            callback_defer: AtomicU32::new(0),
            pending: AtomicBool::new(false),
            mutations: AtomicU32::new(0),
            blockers: AtomicU32::new(0),
            wait,
            wake,
        }
    }

    fn prepare(&self) -> Preparation<'_> {
        let mut value = self.mutations.load(Ordering::Acquire);
        loop {
            if value & FROZEN != 0 {
                // Publish the waiter before parking. Thaw either observes the
                // bit and wakes us, or makes this CAS fail before we can wait.
                let waiting = value | WAITING;
                match self.mutations.compare_exchange(
                    value,
                    waiting,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        (self.wait)(&self.mutations, waiting);
                        value = self.mutations.load(Ordering::Acquire);
                    }
                    Err(current) => value = current,
                }
                continue;
            }
            assert!(value < WAITING - 1, "resource mutation counter overflow");
            match self.mutations.compare_exchange_weak(
                value,
                value + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Preparation(self),
                Err(current) => value = current,
            }
        }
    }

    /// Freeze only an empty, fully published chain. Never walk another
    /// thread's stack or destroy an operation it may still be mutating.
    #[cfg(not(target_os = "mochios"))]
    pub(super) fn capture_empty(&self) -> Option<Capture<'_>> {
        self.capture(true)
    }

    /// Admit stable FD-only scopes without reading their foreign stack nodes.
    /// Every other resource owner remains a blocker until it retires.
    pub(super) fn capture_for_fork(&self) -> Option<Capture<'_>> {
        self.capture(false)
    }

    fn capture(&self, require_empty: bool) -> Option<Capture<'_>> {
        self.mutations
            .compare_exchange(0, FROZEN, Ordering::AcqRel, Ordering::Acquire)
            .ok()?;
        let capture = Capture(self);
        if (require_empty && !self.is_empty())
            || self.is_deferred()
            || self.blockers.load(Ordering::Acquire) != 0
        {
            return None;
        }
        Some(capture)
    }

    /// Child-only detachment. The snapshot held capture_for_fork and no owner
    /// of this chain resumes here. FD pins were reconciled separately. Keep
    /// all private stack/heap memory, and never invoke a foreign destructor.
    ///
    /// # Safety
    /// No detached scope may resume or later be retired in this image.
    pub(super) unsafe fn discard_fork_opaque(&self) -> bool {
        if self.blockers.load(Ordering::Acquire) != 0
            || self.is_deferred()
            || self.mutations.load(Ordering::Acquire) != 0
        {
            return false;
        }
        self.head.store(ptr::null_mut(), Ordering::Release);
        self.pending.store(false, Ordering::Release);
        true
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
        if !self.is_empty()
            || self.is_deferred()
            || self.mutations.load(Ordering::Acquire) != 0
            || self.blockers.load(Ordering::Acquire) != 0
        {
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
        let _preparation = self.prepare();
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
    preparing: Option<Preparation<'a>>,
    fork_opaque: bool,
    _pinned: PhantomPinned,
}

impl<'a, R> Scope<'a, R> {
    pub(super) fn new(chain: &'a Chain, context: u64, resource: R) -> Self {
        let preparing = chain.prepare();
        Self {
            link: Link {
                previous: ptr::null_mut(),
                context,
                active: false,
                discard: discard::<R>,
            },
            chain,
            resource: Some(resource),
            preparing: Some(preparing),
            fork_opaque: false,
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
        scope.chain.blockers.fetch_add(1, Ordering::Release);
        scope.chain.head.store(&mut scope.link, Ordering::Release);
        drop(scope.preparing.take());
    }

    /// # Safety
    /// Publish only after initialization, with callbacks deferred. R and the
    /// remaining operation must retain no native references except FD pins
    /// handled by the child borrow-book transition. Any nested operation that
    /// can obtain temporary Handles must publish its own ordinary scope first.
    /// Ownership metadata must not change until normal retirement/abandonment.
    pub(super) unsafe fn allow_fork_opaque(self: Pin<&mut Self>) {
        let scope = unsafe { self.get_unchecked_mut() };
        let _preparation = scope.chain.prepare();
        assert!(scope.link.active && scope.resource.is_some() && !scope.fork_opaque);
        scope.fork_opaque = true;
        scope.chain.blockers.fetch_sub(1, Ordering::Release);
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
        let _preparation = self.chain.prepare();
        if self.link.active {
            assert_eq!(
                self.chain.head.load(Ordering::Acquire),
                &mut self.link as *mut Link,
                "non-LIFO runtime resource retirement"
            );
            self.chain.head.store(self.link.previous, Ordering::Release);
            self.link.active = false;
            if !self.fork_opaque {
                self.chain.blockers.fetch_sub(1, Ordering::Release);
            }
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
    if !scope.fork_opaque {
        scope.chain.blockers.fetch_sub(1, Ordering::Release);
    }
    drop(scope.resource.take());
}
