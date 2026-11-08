//! Execute the actual C adapters with controlled mechanism replies. No host
//! libc symbol is replaced; these modules export C names on mochiOS only.
#![allow(dead_code)]
use mochios_posix_client::newlib_errno::{EAGAIN, EFAULT, EINVAL, EIO, ENOMEM, ENOTSUP, ESRCH};
use std::{
    cell::RefCell,
    ffi::{c_int, c_void},
};
const PAGE_SIZE: usize = 4096;
type Pthread = u32;
#[repr(C)]
struct SchedParam {
    sched_priority: c_int,
}
#[derive(Default)]
struct State {
    errno: i32,
    calls: Vec<(mnu_abi::SyscallNumber, u64, u64)>,
    discard_error: Option<mnu_abi::status::Error>,
}
thread_local! { static STATE: RefCell<State> = RefCell::new(State::default()); }
fn result_with_errno<T>(result: Result<T, i32>, failure: T) -> T {
    result.unwrap_or_else(|error| {
        STATE.with(|s| s.borrow_mut().errno = error);
        failure
    })
}
fn register_current_thread() -> Option<(u32, ())> {
    Some((1, ()))
}
mod thread_reference {
    pub fn with_live_token<T>(thread: u32, apply: impl FnOnce(&()) -> T) -> Result<T, i32> {
        if thread != 1 {
            return Err(super::ESRCH);
        }
        Ok(apply(&()))
    }
}
mod user_copy {
    pub fn read(source: *const u8, output: &mut [u8]) -> Result<(), i32> {
        if source as usize <= 1 {
            return Err(super::EFAULT);
        }
        unsafe { std::ptr::copy_nonoverlapping(source, output.as_mut_ptr(), output.len()) };
        Ok(())
    }
    pub fn write(destination: *mut u8, input: &[u8]) -> Result<(), i32> {
        if destination as usize <= 1 {
            return Err(super::EFAULT);
        }
        unsafe { std::ptr::copy_nonoverlapping(input.as_ptr(), destination, input.len()) };
        Ok(())
    }
}
mod syscall {
    pub use mnu_abi::SyscallNumber;
    pub struct Raw(u64);
    impl Raw {
        pub fn raw(self) -> u64 {
            self.0
        }
    }
    pub fn raw_syscall2(operation: SyscallNumber, address: u64, length: u64) -> Raw {
        super::STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.calls.push((operation, address, length));
            Raw(if operation == SyscallNumber::MemoryDiscard {
                state.discard_error.map(|e| e.into_raw()).unwrap_or(0)
            } else if address == 0xdead000 {
                mnu_abi::status::Error::InvalidAddress.into_raw()
            } else {
                0
            })
        })
    }
    pub fn raw_syscall4(
        operation: SyscallNumber,
        address: u64,
        length: u64,
        output: u64,
        count: u64,
    ) -> Raw {
        assert_eq!(operation, SyscallNumber::MemoryResidencyRead);
        assert!(count <= 256);
        assert_eq!(count * 4096, length);
        super::STATE.with(|s| s.borrow_mut().calls.push((operation, address, count)));
        unsafe {
            std::slice::from_raw_parts_mut(output as *mut u8, count as usize).fill(1);
        }
        Raw(count)
    }
}
#[path = "../../newlib-runtime/src/memory_extensions.rs"]
mod memory_extensions;
#[path = "../../newlib-runtime/src/pthread_schedule.rs"]
mod pthread_schedule;

#[test]
fn residency_chunks_large_ranges_and_rejects_bad_alignment_holes_and_overflow() {
    let mut vector = vec![0; 513];
    assert_eq!(
        unsafe {
            memory_extensions::mincore(0x100000 as *mut _, 512 * PAGE_SIZE + 1, vector.as_mut_ptr())
        },
        0
    );
    assert_eq!(vector, vec![1; 513]);
    STATE.with(|state| {
        let state = state.borrow();
        assert_eq!(state.calls.len(), 4); // complete-range validation + 3 observations
        assert_eq!(state.calls[1].2, 256);
        assert_eq!(state.calls[2].2, 256);
        assert_eq!(state.calls[3].2, 1);
    });
    for (address, length, expected) in [
        (0x1001, 1, EINVAL),
        (usize::MAX & !4095, 8192, ENOMEM),
        (0xdead000, 1, ENOMEM),
    ] {
        assert_eq!(
            unsafe { memory_extensions::mincore(address as *mut _, length, vector.as_mut_ptr()) },
            -1
        );
        STATE.with(|s| assert_eq!(s.borrow().errno, expected));
    }
    assert_eq!(
        unsafe { memory_extensions::mincore(0x1000 as *mut _, 0, std::ptr::null_mut()) },
        0
    );
}

#[test]
fn destructive_advice_uses_discard_and_cannot_fake_success_for_unsupported_backing() {
    STATE.with(|s| s.borrow_mut().errno = 57);
    assert_eq!(memory_extensions::madvise(0x4000 as *mut _, 4097, 4), 0);
    STATE.with(|s| {
        assert_eq!(
            s.borrow().calls.last(),
            Some(&(mnu_abi::SyscallNumber::MemoryDiscard, 0x4000, 8192))
        );
        assert_eq!(s.borrow().errno, 57);
        s.borrow_mut().discard_error = Some(mnu_abi::status::Error::Unsupported);
    });
    assert_eq!(memory_extensions::madvise(0x4000 as *mut _, 4096, 4), -1);
    STATE.with(|s| assert_eq!(s.borrow().errno, ENOTSUP));
    for advice in 0..4 {
        assert_eq!(memory_extensions::madvise(0x4000 as *mut _, 1, advice), 0);
    }
    assert_eq!(memory_extensions::madvise(0x4001 as *mut _, 1, 0), -1);
    assert_eq!(memory_extensions::madvise(0x4000 as *mut _, 1, 8), -1);
}

#[test]
fn pthread_scheduling_preserves_errno_rejects_stale_tokens_and_does_not_claim_realtime_support() {
    let mut policy = -9;
    let mut parameter = SchedParam { sched_priority: -9 };
    STATE.with(|s| s.borrow_mut().errno = 57);
    assert_eq!(
        unsafe { pthread_schedule::pthread_getschedparam(1, &mut policy, &mut parameter) },
        0
    );
    assert_eq!((policy, parameter.sched_priority), (0, 0));
    assert_eq!(
        unsafe { pthread_schedule::pthread_setschedparam(1, 0, &parameter) },
        0
    );
    assert_eq!(
        unsafe { pthread_schedule::pthread_getschedparam(9, &mut policy, &mut parameter) },
        ESRCH
    );
    parameter.sched_priority = 1;
    assert_eq!(
        unsafe { pthread_schedule::pthread_setschedparam(1, 1, &parameter) },
        ENOTSUP
    );
    assert_eq!(
        unsafe { pthread_schedule::pthread_setschedparam(1, 0, &parameter) },
        EINVAL
    );
    assert_eq!(
        unsafe { pthread_schedule::pthread_setschedparam(1, 7, &parameter) },
        EINVAL
    );
    assert_eq!(
        unsafe { pthread_schedule::pthread_getschedparam(1, std::ptr::null_mut(), &mut parameter) },
        EINVAL
    );
    STATE.with(|s| assert_eq!(s.borrow().errno, 57));
}
