//! Process-local fork callbacks. Storage is append-only and allocated only
//! during registration; executing a captured prefix allocates and locks nothing.
use core::{alloc::Layout, ptr};

pub type Callback = unsafe extern "C" fn();

#[derive(Clone, Copy, Default)]
pub struct Handlers {
    pub prepare: Option<Callback>,
    pub parent: Option<Callback>,
    pub child: Option<Callback>,
}

struct Node {
    handlers: Handlers,
    previous: *const Node,
    next: *mut Node,
}

pub struct Registry {
    first: *mut Node,
    last: *mut Node,
    count: usize,
}

// Nodes belong to this process and are never freed. Mutations require exclusive
// access; an external mutex must serialize registration and snapshot capture.
unsafe impl Send for Registry {}

impl Registry {
    pub const fn new() -> Self {
        Self {
            first: ptr::null_mut(),
            last: ptr::null_mut(),
            count: 0,
        }
    }

    /// Register process-lifetime storage. Allocation failure does not publish a
    /// partial record. There is no allocation or artificial callback-count cap
    /// on the fork path.
    ///
    /// # Safety
    /// `allocate` must return null or a new valid allocation for the requested
    /// Layout. Ownership is transferred here and it must live until process exit.
    pub unsafe fn register(
        &mut self,
        handlers: Handlers,
        allocate: impl FnOnce(Layout) -> *mut u8,
    ) -> Result<(), ()> {
        let count = self.count.checked_add(1).ok_or(())?;
        let node = allocate(Layout::new::<Node>()).cast::<Node>();
        if node.is_null() {
            return Err(());
        }
        unsafe {
            node.write(Node {
                handlers,
                previous: self.last,
                next: ptr::null_mut(),
            });
            if self.last.is_null() {
                self.first = node;
            } else {
                (*self.last).next = node;
            }
        }
        self.last = node;
        self.count = count;
        Ok(())
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            first: self.first,
            last: self.last,
            count: self.count,
        }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
pub struct Snapshot {
    first: *const Node,
    last: *const Node,
    count: usize,
}

impl Snapshot {
    /// # Safety
    /// Every registered callback must be callable in the invoking thread.
    pub unsafe fn prepare(self) {
        let mut cursor = self.last;
        for _ in 0..self.count {
            // previous/handlers are immutable after publication.
            // Read only immutable fields, not a shared reference to the whole
            // Node: registration may write this tail node's next field.
            let previous = unsafe { (*cursor).previous };
            let callback = unsafe { (*cursor).handlers.prepare };
            cursor = previous;
            if let Some(callback) = callback {
                unsafe { callback() };
            }
        }
    }

    /// # Safety
    /// Every registered callback must be callable in the invoking thread.
    pub unsafe fn parent(self) {
        unsafe { self.finish(false) };
    }

    /// # Safety
    /// Every registered callback must be callable in the invoking thread.
    pub unsafe fn child(self) {
        unsafe { self.finish(true) };
    }

    unsafe fn finish(self, child: bool) {
        let mut cursor = self.first;
        for index in 0..self.count {
            // Do not read the captured tail's next field: a concurrent
            // registration may append there. Earlier links are immutable.
            let handlers = unsafe { (*cursor).handlers };
            if index + 1 < self.count {
                cursor = unsafe { (*cursor).next };
            }
            let callback = if child {
                handlers.child
            } else {
                handlers.parent
            };
            if let Some(callback) = callback {
                unsafe { callback() };
            }
        }
    }
}
