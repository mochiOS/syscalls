//! Run with rustc --test; exercise the exported C entry point with checked boundaries.
#![allow(dead_code, non_camel_case_types)]
use std::cell::Cell;
type c_int = i32;
const EINVAL: c_int = 22;
const EFAULT: c_int = 14;
thread_local! {
    static QUERY_ERROR: Cell<i32> = const { Cell::new(0) };
    static COPY_ERROR: Cell<i32> = const { Cell::new(0) };
    static LAST_ERROR: Cell<i32> = const { Cell::new(0) };
    static QUERIES: Cell<usize> = const { Cell::new(0) };
}
fn map_kernel_errno(e: i64) -> i32 {
    e as i32
}
fn result_with_errno(result: Result<i32, i32>, failure: i32) -> i32 {
    match result {
        Ok(v) => v,
        Err(e) => {
            LAST_ERROR.set(e);
            failure
        }
    }
}
mod syscall {
    pub struct Error(pub i64);
    impl Error {
        pub fn raw(self) -> i64 {
            self.0
        }
    }
    pub struct Usage {
        pub current_bytes: u64,
        pub peak_bytes: u64,
    }
    pub mod execution {
        pub fn memory_usage(handle: Option<u32>) -> Result<super::Usage, super::Error> {
            assert_eq!(handle, None, "C API must only query its caller");
            crate::QUERIES.set(crate::QUERIES.get() + 1);
            let e = crate::QUERY_ERROR.get();
            if e != 0 {
                return Err(super::Error(e as i64));
            }
            Ok(super::Usage {
                current_bytes: 0x123456789,
                peak_bytes: 0x23456789a,
            })
        }
    }
}
mod user_copy {
    pub fn write(output: *mut u8, bytes: &[u8]) -> Result<(), i32> {
        let e = crate::COPY_ERROR.get();
        if e != 0 {
            return Err(e);
        }
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
        Ok(())
    }
}
#[path = "../src/process_memory.rs"]
mod implementation;
unsafe extern "C" {
    fn mochios_process_memory_read(output: *mut u8, size: usize) -> i32;
}
#[test]
fn exact_size_and_null_are_rejected_without_a_kernel_query() {
    for size in [0, 15, 17, usize::MAX] {
        let mut out = [0xa5; 16];
        assert_eq!(
            unsafe { mochios_process_memory_read(out.as_mut_ptr(), size) },
            -1
        );
        assert_eq!(LAST_ERROR.get(), EINVAL);
        assert_eq!(out, [0xa5; 16]);
    }
    assert_eq!(
        unsafe { mochios_process_memory_read(std::ptr::null_mut(), 16) },
        -1
    );
    assert_eq!(LAST_ERROR.get(), EFAULT);
    assert_eq!(QUERIES.get(), 0);
}
#[test]
fn snapshot_uses_exact_native_u64_bytes_and_one_self_query() {
    let mut out = [0; 16];
    assert_eq!(
        unsafe { mochios_process_memory_read(out.as_mut_ptr(), 16) },
        0
    );
    assert_eq!(
        u64::from_ne_bytes(out[..8].try_into().unwrap()),
        0x123456789
    );
    assert_eq!(
        u64::from_ne_bytes(out[8..].try_into().unwrap()),
        0x23456789a
    );
    assert_eq!(QUERIES.get(), 1);
}
#[test]
fn kernel_and_checked_copy_errors_are_propagated() {
    let mut out = [0xa5; 16];
    QUERY_ERROR.set(38);
    assert_eq!(
        unsafe { mochios_process_memory_read(out.as_mut_ptr(), 16) },
        -1
    );
    assert_eq!(LAST_ERROR.get(), 38);
    assert_eq!(out, [0xa5; 16]);
    QUERY_ERROR.set(0);
    COPY_ERROR.set(EFAULT);
    assert_eq!(unsafe { mochios_process_memory_read(1 as *mut u8, 16) }, -1);
    assert_eq!(LAST_ERROR.get(), EFAULT);
}
