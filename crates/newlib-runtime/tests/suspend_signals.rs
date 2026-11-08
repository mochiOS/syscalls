//! Exercise the real wait sequencing independently of host signal interposition.
#![allow(dead_code)]
use std::cell::Cell;
#[path = "../src/suspend_signals.rs"]
mod implementation;

#[test]
fn already_caught_handler_never_waits() {
    assert_eq!(
        implementation::wait::<i32>(
            1,
            || 2,
            || panic!("no epoch request"),
            || panic!("no drain"),
            |_| panic!("no sleep")
        ),
        Ok(())
    );
}

#[test]
fn arrival_between_drain_and_wait_cannot_be_lost() {
    let generation = Cell::new(0);
    let pending = Cell::new(false);
    let epoch = Cell::new(7);
    let requests = Cell::new(0);
    let result = implementation::wait::<i32>(
        0,
        || generation.get(),
        || Ok(epoch.get()),
        || {
            if pending.replace(false) {
                generation.set(1);
            }
            Ok(())
        },
        |observed| {
            assert_eq!(observed, 7);
            requests.set(requests.get() + 1);
            // Arrives at the retained request's admission boundary.
            epoch.set(8);
            pending.set(true);
            Ok(())
        },
    );
    assert_eq!(result, Ok(()));
    assert_eq!(requests.get(), 1);
    assert_eq!(generation.get(), 1);
}

#[test]
fn epoch_or_ignored_signal_wakeup_is_not_a_caught_handler() {
    let generation = Cell::new(0);
    let pending = Cell::new(false);
    let requests = Cell::new(0);
    let result = implementation::wait::<i32>(
        0,
        || generation.get(),
        || Ok(requests.get()),
        || {
            if pending.replace(false) {
                generation.set(1);
            }
            Ok(())
        },
        |observed| {
            assert_eq!(observed, requests.get());
            let count = requests.get() + 1;
            requests.set(count);
            if count == 2 {
                pending.set(true);
            }
            assert!(count <= 2);
            Ok(())
        },
    );
    assert_eq!(result, Ok(()));
    assert_eq!(requests.get(), 2);
}

#[test]
fn caught_during_drain_skips_sleep_and_errors_propagate() {
    let generation = Cell::new(0);
    assert_eq!(
        implementation::wait::<i32>(
            0,
            || generation.get(),
            || Ok(9),
            || {
                generation.set(1);
                Ok(())
            },
            |_| panic!("must not wait")
        ),
        Ok(())
    );
    assert_eq!(
        implementation::wait::<i32>(0, || 0, || Err(38), || panic!(), |_| panic!()),
        Err(38)
    );
    assert_eq!(
        implementation::wait::<i32>(0, || 0, || Ok(1), || Ok(()), |_| Err(5)),
        Err(5)
    );
}
