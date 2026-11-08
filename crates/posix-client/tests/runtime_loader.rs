//! C ABI and reentrant callback tests execute the actual runtime adapters.
#![allow(dead_code)]
use mochios_posix_client::{
    loaded_objects,
    newlib_errno::*,
    pie::{Pie, link_scope::Object},
};
use std::{
    cell::RefCell,
    ffi::{c_char, c_int, c_void},
    ptr,
    sync::atomic::{AtomicUsize, Ordering},
};
#[path = "common/loaded_image.rs"]
mod common;
thread_local! { static METADATA: RefCell<Vec<u8>> = RefCell::new(Vec::new()); static ERRNO: RefCell<i32> = const { RefCell::new(0) }; }
fn result_with_errno<T>(result: Result<T, i32>, failure: T) -> T {
    result.unwrap_or_else(|error| {
        ERRNO.with(|s| *s.borrow_mut() = error);
        failure
    })
}
mod auxiliary {
    pub struct Vector;
    pub fn vector() -> Option<Vector> {
        Some(Vector)
    }
    impl Vector {
        pub fn lookup(&self, _: usize) -> Result<usize, i32> {
            super::METADATA.with(|s| Ok(s.borrow().as_ptr() as usize))
        }
    }
}
mod startup_storage {
    pub struct Buffer(Vec<u8>);
    impl Buffer {
        pub fn new(length: usize) -> Result<Self, i32> {
            Ok(Self(vec![0; length]))
        }
        pub fn bytes(&self) -> &[u8] {
            &self.0
        }
        pub fn bytes_mut(&mut self) -> &mut [u8] {
            &mut self.0
        }
        pub fn into_raw(mut self) -> (usize, usize) {
            let result = (self.0.as_mut_ptr() as usize, self.0.capacity());
            std::mem::forget(self);
            result
        }
    }
}
mod user_copy {
    pub fn read(source: *const u8, bytes: &mut [u8]) -> Result<(), i32> {
        if source as usize <= 1 {
            return Err(super::EFAULT);
        }
        unsafe { ptr::copy_nonoverlapping(source, bytes.as_mut_ptr(), bytes.len()) };
        Ok(())
    }
    pub fn write(destination: *mut u8, bytes: &[u8]) -> Result<(), i32> {
        if destination as usize <= 1 {
            return Err(super::EFAULT);
        }
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), destination, bytes.len()) };
        Ok(())
    }
    use std::ptr;
}
mod executable_name {
    pub fn getexecname() -> *const std::ffi::c_char {
        c"/system/bin/example".as_ptr()
    }
}
mod dlfcn {
    pub fn inspect<T: Copy>(visit: impl FnOnce(&[&[u8]]) -> Result<T, i32>) -> Result<T, i32> {
        visit(&[super::loader_inspection::initial()])
    }
}
mod io_resources {
    pub fn with<R, T>(
        create: impl FnOnce() -> Result<R, i32>,
        apply: impl FnOnce(&mut R) -> Result<T, i32>,
    ) -> Result<T, i32> {
        apply(&mut create()?)
    }
}
#[path = "../../newlib-runtime/src/loader_inspection.rs"]
mod loader_inspection;

#[test]
fn c_layout_address_lookup_snapshot_and_reentrant_early_stop_callback() {
    let source = common::source();
    let image = Pie::parse_object(&source).unwrap();
    let objects = [Object {
        name: b"",
        image: &image,
        bias: 0x20000000,
    }];
    let mut encoded = vec![0; loaded_objects::encoded_length(&objects, b"").unwrap()];
    loaded_objects::encode(&objects, b"", &mut encoded).unwrap();
    METADATA.with(|s| *s.borrow_mut() = encoded);
    loader_inspection::initialize().unwrap();
    // Changing the original auxiliary-vector metadata cannot change inspection.
    METADATA.with(|s| s.borrow_mut().fill(0xa5));
    let mut output = [usize::MAX; 4];
    assert_eq!(std::mem::size_of::<loader_inspection::DlInfo>(), 32);
    assert_eq!(std::mem::size_of::<loader_inspection::DlPhdrInfo>(), 32);
    assert_eq!(
        unsafe { loader_inspection::dladdr(0x20001000 as *const _, output.as_mut_ptr().cast()) },
        1
    );
    assert_eq!(output[1], 0x20000000);
    assert_eq!(
        unsafe { std::ffi::CStr::from_ptr(output[0] as *const c_char) }.to_bytes(),
        b"/system/bin/example"
    );
    assert_eq!((output[2], output[3]), (0, 0));
    let prior = output;
    assert_eq!(
        unsafe { loader_inspection::dladdr(0x30000000 as *const _, output.as_mut_ptr().cast()) },
        0
    );
    assert_eq!(output, prior);
    assert_eq!(
        unsafe { loader_inspection::dladdr(0x20001000 as *const _, ptr::null_mut()) },
        0
    );
    ERRNO.with(|s| assert_eq!(*s.borrow(), EFAULT));
    unsafe extern "C" fn callback(
        info: *mut loader_inspection::DlPhdrInfo,
        size: usize,
        data: *mut c_void,
    ) -> c_int {
        assert_eq!(size, 32);
        let fields = unsafe { std::slice::from_raw_parts(info.cast::<u64>(), 4) };
        assert_eq!(fields[0], 0x20000000);
        assert_eq!(fields[3] & 0xffff, 1);
        let counter = unsafe { &mut *data.cast::<u32>() };
        *counter += 1;
        let mut output = [0usize; 4];
        assert_eq!(
            unsafe {
                loader_inspection::dladdr(0x20001000 as *const _, output.as_mut_ptr().cast())
            },
            1
        );
        17
    }
    let mut calls = 0u32;
    assert_eq!(
        unsafe {
            loader_inspection::dl_iterate_phdr(Some(callback), (&mut calls as *mut u32).cast())
        },
        17
    );
    assert_eq!(calls, 1);
    assert_eq!(
        unsafe { loader_inspection::dl_iterate_phdr(None, ptr::null_mut()) },
        -1
    );
}
