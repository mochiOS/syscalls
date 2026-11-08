//! Test the real stack resolver independently of host pthread interposition.
#![allow(dead_code, non_camel_case_types)]
type c_int = i32;
const EINVAL: c_int = 22;
const ENOTSUP: c_int = 95;
const PTHREAD_STACK_MIN: usize = 16384;
#[path = "../src/thread_stack_info.rs"]
mod info;
use info::{Observed, Stack};
fn worker(base: usize, size: usize, guard: usize, owned: bool) -> Observed {
    Observed {
        base,
        reservation_size: size,
        guard_size: guard,
        owned,
        initial: false,
    }
}
#[test]
fn owned_and_caller_supplied_stacks_keep_their_real_extents() {
    let s = info::resolve(worker(0x10000, 0x20000, 0x2000, true), || {
        panic!("worker does not query initial stack")
    })
    .unwrap();
    assert_eq!(
        s,
        Stack {
            base: 0x12000,
            size: 0x1e000,
            guard_size: 0x2000
        }
    );
    let s = info::resolve(worker(0x10000, 0x20000, 0, false), || panic!()).unwrap();
    assert_eq!(
        s,
        Stack {
            base: 0x10000,
            size: 0x20000,
            guard_size: 0
        }
    );
}
#[test]
fn unknown_foreign_and_inconsistent_stacks_never_fall_back_to_main() {
    for (o, error) in [
        (worker(0, 0, 0, false), ENOTSUP),
        (worker(0, 0x10000, 0, true), EINVAL),
        (worker(0x10000, 0x1000, 0, true), EINVAL),
        (worker(0x10000, 0x10000, 0x10000, true), EINVAL),
        (worker(0x10000, 0x10000, 1, false), EINVAL),
        (worker(usize::MAX, 0x10000, 0, true), EINVAL),
    ] {
        assert_eq!(
            info::resolve(o, || panic!("no guessed initial bounds")),
            Err(error)
        );
    }
}
#[test]
fn initial_thread_uses_kernel_snapshot_and_propagates_absence() {
    let observed = || Observed {
        base: 0,
        reservation_size: 0,
        guard_size: 0,
        owned: false,
        initial: true,
    };
    let s = info::resolve(observed(), || {
        Ok(mnu_abi::ProcessInitialStackInfo {
            lower_bound: 0x10000,
            committed_lower_bound: 0x1c000,
            upper_bound: 0x30000,
        })
    })
    .unwrap();
    assert_eq!(
        s,
        Stack {
            base: 0x10000,
            size: 0x20000,
            guard_size: 0
        }
    );
    assert_eq!(info::resolve(observed(), || Err(38)), Err(38));
    for (low, committed, top) in [
        (0, 0x10000, 0x30000),
        (0x20000, 0x10000, 0x30000),
        (0x10000, 0x30000, 0x30000),
        (0x10000, 0x10000, 0x10001),
    ] {
        assert_eq!(
            info::resolve(observed(), || Ok(mnu_abi::ProcessInitialStackInfo {
                lower_bound: low,
                committed_lower_bound: committed,
                upper_bound: top
            })),
            Err(EINVAL)
        );
    }
}
