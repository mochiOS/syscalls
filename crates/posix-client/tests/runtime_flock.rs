//! Run the real flock adapter, including waiting/reference cleanup, without
//! replacing the host's libc or granting a fake filesystem authority.
#![allow(dead_code)]
use mochios_posix_client::newlib_errno::{EAGAIN, EBADF, EINTR, EINVAL, EIO, ENOTSUP};
use std::{
    cell::RefCell,
    collections::VecDeque,
    ffi::c_int,
    ops::Deref,
    sync::atomic::{AtomicU32, Ordering},
};
#[derive(Clone, Copy, PartialEq)]
enum FdKind {
    ObjectFile,
    Pipe,
}
#[derive(Clone, Copy)]
struct Handle {
    kind: FdKind,
    lower_handle: u64,
}
#[derive(Clone, Copy)]
struct FdEntry {
    handle: Handle,
}
struct ThreadControl {
    nonrestart_signal_generation: AtomicU32,
}
static CONTROL: ThreadControl = ThreadControl {
    nonrestart_signal_generation: AtomicU32::new(0),
};
#[derive(Default)]
struct State {
    replies: VecDeque<Result<u64, i32>>,
    calls: Vec<(u64, u32)>,
    sleeps: usize,
    pins: usize,
    interrupt: bool,
    inherited: bool,
    errno: i32,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
struct Lease(FdEntry);
impl Deref for Lease {
    type Target = FdEntry;
    fn deref(&self) -> &FdEntry {
        &self.0
    }
}
impl Lease {
    fn is_current(&self) -> bool {
        STATE.with(|s| !s.borrow().inherited)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        STATE.with(|s| s.borrow_mut().pins -= 1);
    }
}
fn with_fd_entry(fd: c_int) -> Result<Lease, i32> {
    if fd < 0 {
        return Err(EBADF);
    }
    STATE.with(|s| s.borrow_mut().pins += 1);
    Ok(Lease(FdEntry {
        handle: Handle {
            kind: if fd == 9 {
                FdKind::Pipe
            } else {
                FdKind::ObjectFile
            },
            lower_handle: 73,
        },
    }))
}
fn register_current_thread() -> Option<(u32, &'static ThreadControl)> {
    Some((1, &CONTROL))
}
fn io_cancellation_requested(_: &ThreadControl) -> bool {
    false
}
fn defer_native_delivery() {}
fn drain_pending_signals() -> Result<(), i32> {
    if STATE.with(|s| s.borrow().interrupt) {
        CONTROL
            .nonrestart_signal_generation
            .fetch_add(1, Ordering::Release);
    }
    Ok(())
}
fn syscall_errno(result: Result<u64, i32>) -> Result<u64, i32> {
    result
}
fn result_with_errno<T>(result: Result<T, i32>, failure: T) -> T {
    result.unwrap_or_else(|error| {
        STATE.with(|s| s.borrow_mut().errno = error);
        failure
    })
}
mod syscall {
    pub use mnu_abi::SyscallNumber;
    pub fn raw_syscall6(
        op: SyscallNumber,
        handle: u64,
        selector: u64,
        input: u64,
        length: u64,
        output: u64,
        capacity: u64,
    ) -> Result<u64, i32> {
        assert_eq!(op, SyscallNumber::HandleControl);
        assert_eq!(
            selector,
            mochios_filesystem_protocol::whole_file_lock::UPDATE
        );
        assert_eq!((length, output, capacity), (4, 0, 0));
        let mode = unsafe { std::ptr::read_unaligned(input as *const u32) };
        assert!(matches!(mode, 1 | 2 | 8));
        super::STATE.with(|s| {
            let mut s = s.borrow_mut();
            s.calls.push((handle, mode));
            s.replies.pop_front().unwrap()
        })
    }
    pub fn raw_syscall1(op: SyscallNumber, milliseconds: u64) -> Result<u64, i32> {
        assert_eq!(op, SyscallNumber::Sleep);
        assert_eq!(milliseconds, 2);
        super::STATE.with(|s| s.borrow_mut().sleeps += 1);
        Ok(0)
    }
}
mod io_resources {
    pub unsafe fn with_fork_opaque<R, T>(
        create: impl FnOnce() -> Result<R, i32>,
        observe: impl FnOnce(&R) -> bool,
        apply: impl FnOnce(&mut R) -> Result<T, i32>,
    ) -> Result<T, i32> {
        let mut resource = create()?;
        assert!(observe(&resource));
        apply(&mut resource)
    }
}
#[path = "../../newlib-runtime/src/whole_file_lock.rs"]
mod implementation;
fn setup(replies: impl IntoIterator<Item = Result<u64, i32>>) {
    STATE.with(|s| {
        *s.borrow_mut() = State {
            replies: replies.into_iter().collect(),
            ..Default::default()
        }
    });
}
#[test]
fn real_adapter_waits_only_for_contention_and_releases_pins_on_every_exit() {
    setup([]);
    assert_eq!(implementation::flock(1, 3), -1);
    assert_eq!(implementation::flock(1, 16), -1);
    assert_eq!(implementation::flock(-1, 2), -1);
    assert_eq!(implementation::flock(9, 2), -1);
    STATE.with(|s| {
        assert_eq!(s.borrow().pins, 0);
        assert!(s.borrow().calls.is_empty());
    });
    setup([Err(EAGAIN)]);
    assert_eq!(implementation::flock(1, 2 | 4), -1);
    STATE.with(|s| {
        let s = s.borrow();
        assert_eq!(s.errno, EAGAIN);
        assert_eq!(s.sleeps, 0);
        assert_eq!(s.pins, 0);
    });
    setup([Err(EAGAIN), Ok(0)]);
    assert_eq!(implementation::flock(1, 2), 0);
    STATE.with(|s| {
        let s = s.borrow();
        assert_eq!(s.calls, [(73, 2), (73, 2)]);
        assert_eq!(s.sleeps, 1);
        assert_eq!(s.pins, 0);
    });
    setup([Err(EAGAIN)]);
    STATE.with(|s| s.borrow_mut().interrupt = true);
    assert_eq!(implementation::flock(1, 1), -1);
    STATE.with(|s| {
        let s = s.borrow();
        assert_eq!(s.errno, EINTR);
        assert_eq!(s.sleeps, 0);
        assert_eq!(s.pins, 0);
    });
    setup([Err(ENOTSUP)]);
    assert_eq!(implementation::flock(1, 1), -1);
    STATE.with(|s| {
        assert_eq!(s.borrow().errno, ENOTSUP);
        assert_eq!(s.borrow().pins, 0);
    });
    setup([Ok(0)]);
    assert_eq!(implementation::flock(1, 8 | 4), 0);
    STATE.with(|s| {
        assert_eq!(s.borrow().calls, [(73, 8)]);
        assert_eq!(s.borrow().pins, 0);
    });
}
