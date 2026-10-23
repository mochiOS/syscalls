//! Allocation-free tracking of held newlib locks. Only this process's runtime
//! accesses the intrusive list; the kernel knows neither libc nor its owners.
use super::*;

pub(super) struct Registry {
    head: usize,
    frozen_by: u64,
}

static LOCKS: RuntimeMutex<Registry> = RuntimeMutex::new(Registry {
    head: 0,
    frozen_by: 0,
});
static EPOCH: AtomicU32 = AtomicU32::new(0);

enum Attempt {
    Acquired,
    Busy,
    Frozen(u32),
}

// The C lock contract keeps a held lock alive until its owner releases it.
// All links are accessed under LOCKS. Register only after acquisition and
// unlink before native release, so no unlocked/freed lock can enter a walk.
fn attempt(lock: &LockOpaque, waiting: bool, contended: bool) -> Attempt {
    let owner = newlib_lock_identity();
    let mut registry = LOCKS.lock();
    if registry.frozen_by != 0 && registry.frozen_by != owner {
        return Attempt::Frozen(EPOCH.load(Ordering::Acquire));
    }
    if !native_mutex_try_acquire(&lock.state) {
        if waiting {
            let _ = lock
                .state
                .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire);
        }
        return Attempt::Busy;
    }
    // A woken contender must retain the waiter bit for sleepers left behind.
    // Otherwise its next unlock could strand them on the native address wait.
    if contended {
        lock.state.store(2, Ordering::Relaxed);
    }
    lock.owner.store(owner, Ordering::Relaxed);
    lock.depth.store(1, Ordering::Relaxed);
    lock.previous.store(0, Ordering::Relaxed);
    lock.next.store(registry.head, Ordering::Relaxed);
    if registry.head != 0 {
        unsafe { &*(registry.head as *const LockOpaque) }
            .previous
            .store(ptr::from_ref(lock) as usize, Ordering::Relaxed);
    }
    registry.head = ptr::from_ref(lock) as usize;
    Attempt::Acquired
}

pub(super) fn acquire(lock: &LockOpaque) {
    let mut contended = false;
    loop {
        match attempt(lock, true, contended) {
            Attempt::Acquired => return,
            Attempt::Frozen(epoch) => native_mutex_wait(&EPOCH, epoch),
            Attempt::Busy => {
                contended = true;
                native_mutex_wait(&lock.state, 2);
            }
        }
    }
}

pub(super) fn try_acquire(lock: &LockOpaque) -> bool {
    matches!(attempt(lock, false, false), Attempt::Acquired)
}

pub(super) fn release(lock: &LockOpaque) {
    let mut registry = LOCKS.lock();
    if lock.owner.load(Ordering::Acquire) != newlib_lock_identity()
        || lock.depth.load(Ordering::Relaxed) != 1
    {
        process_exit(127);
    }
    let previous = lock.previous.load(Ordering::Relaxed);
    let next = lock.next.load(Ordering::Relaxed);
    if previous == 0 {
        if registry.head != ptr::from_ref(lock) as usize {
            process_exit(127);
        }
        registry.head = next;
    } else {
        unsafe { &*(previous as *const LockOpaque) }
            .next
            .store(next, Ordering::Relaxed);
    }
    if next != 0 {
        unsafe { &*(next as *const LockOpaque) }
            .previous
            .store(previous, Ordering::Relaxed);
    }
    lock.previous.store(0, Ordering::Relaxed);
    lock.next.store(0, Ordering::Relaxed);
    lock.owner.store(0, Ordering::Release);
    lock.depth.store(0, Ordering::Relaxed);
    native_mutex_release(&lock.state);
}

pub(super) struct Capture {
    owner: u64,
    _thread: core::marker::PhantomData<*mut ()>,
}

/// Refuse an active foreign libc critical section rather than copying its
/// partial state or taking libc locks in an invented global lock order.
/// Caller-owned recursion is retained, including malloc around VM capture.
pub(super) fn capture() -> Result<Capture, c_int> {
    let owner = newlib_lock_identity();
    if owner == 0 {
        return Err(EAGAIN);
    }
    let mut registry = LOCKS.lock();
    if registry.frozen_by != 0 {
        return Err(EAGAIN);
    }
    let mut pointer = registry.head;
    while pointer != 0 {
        let lock = unsafe { &*(pointer as *const LockOpaque) };
        if lock.owner.load(Ordering::Acquire) != owner {
            return Err(EAGAIN);
        }
        pointer = lock.next.load(Ordering::Relaxed);
    }
    registry.frozen_by = owner;
    Ok(Capture {
        owner,
        _thread: core::marker::PhantomData,
    })
}

impl Capture {
    /// Hold the bookkeeping mutex across the actual VM snapshot too: foreign
    /// waiters can inspect the frozen flag, so merely freezing that flag would
    /// still allow a copied mutex owned by a vanished sibling.
    pub(super) fn freeze_registry(&self) -> RuntimeMutexGuard<'_, Registry> {
        let registry = LOCKS.lock();
        if registry.frozen_by != self.owner {
            process_exit(127);
        }
        registry
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        {
            let mut registry = LOCKS.lock();
            if registry.frozen_by != self.owner {
                process_exit(127);
            }
            registry.frozen_by = 0;
            EPOCH.fetch_add(1, Ordering::Release);
        }
        native_mutex_wake_all(&EPOCH);
    }
}
