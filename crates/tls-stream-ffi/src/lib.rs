//! Private Rust half of the native TLS archive. Only native/tls.c owns these
//! pointers; public callers use never-reused integer handles. No socket, file,
//! root replacement or certificate-verification bypass is exposed.
#![no_std]
#![feature(alloc_error_handler)]
extern crate alloc;

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    alloc::{GlobalAlloc, Layout},
    ffi::{c_int, c_void},
    ptr, slice,
};
use mochios_tls_client::{self as tls, TlsError, TlsState, stream::Stream};

#[cfg(all(
    feature = "test-fixtures",
    any(target_os = "mochios", target_os = "none")
))]
compile_error!("Test certificate trust cannot be built for mochiOS");

unsafe extern "C" {
    fn memalign(alignment: usize, size: usize) -> *mut c_void;
    fn free(pointer: *mut c_void);
    fn abort() -> !;
}

struct ProcessAllocator;
unsafe impl GlobalAlloc for ProcessAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // The C process owns the one allocator; no second runtime is embedded.
        unsafe {
            memalign(
                layout.align().max(core::mem::align_of::<usize>()),
                layout.size().max(1),
            )
            .cast()
        }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, _layout: Layout) {
        unsafe { free(pointer.cast()) }
    }
}
#[global_allocator]
static ALLOCATOR: ProcessAllocator = ProcessAllocator;
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { abort() }
}
#[alloc_error_handler]
fn oom(_: Layout) -> ! {
    unsafe { abort() }
}

#[cfg(any(target_os = "mochios", target_os = "none"))]
getrandom::register_custom_getrandom!(tls::platform_getrandom);

#[cfg(not(any(target_os = "mochios", target_os = "none")))]
#[derive(Debug)]
struct HostTime;
#[cfg(not(any(target_os = "mochios", target_os = "none")))]
impl tls::rustls::time_provider::TimeProvider for HostTime {
    fn current_time(&self) -> Option<tls::rustls::pki_types::UnixTime> {
        unsafe extern "C" {
            fn time(destination: *mut i64) -> i64;
        }
        let seconds = unsafe { time(ptr::null_mut()) };
        u64::try_from(seconds).ok().map(|s| {
            tls::rustls::pki_types::UnixTime::since_unix_epoch(core::time::Duration::from_secs(s))
        })
    }
}

fn code(error: TlsError) -> c_int {
    match error {
        TlsError::InvalidServerName => 1,
        TlsError::InvalidConfiguration => 2,
        TlsError::RandomUnavailable => 3,
        TlsError::TimeUnavailable => 4,
        TlsError::CertificateInvalid => 5,
        TlsError::HostnameMismatch => 6,
        TlsError::CertificateChainTooDeep => 7,
        TlsError::CertificateTooLarge => 8,
        TlsError::CertificateChainTooLarge => 9,
        TlsError::AuthenticationFailed => 10,
        TlsError::BufferLimit => 11,
        TlsError::Protocol => 12,
        TlsError::PeerAlert => 13,
        TlsError::InvalidState => 14,
    }
}
fn result(value: Result<(), TlsError>) -> c_int {
    value.map_or_else(code, |()| 0)
}

#[repr(C)]
struct Status {
    state: u32,
    receive: u32,
    transmit: u32,
    protocol: u16,
    cipher: u16,
}

// SAFETY CONTRACT for all private entry points: tls.c holds its registry mutex;
// stream is its unique live Box, and all buffers are C-owned scratch storage
// with checked extents. Application pointers never become Rust references.

#[unsafe(no_mangle)]
unsafe extern "C" fn _mochi_tls_core_new(
    host: *const u8,
    host_len: usize,
    alpn: *const u8,
    alpn_len: usize,
    out: *mut *mut Stream,
) -> c_int {
    let create = || -> Result<Stream, TlsError> {
        if host_len == 0 || host_len > tls::MAX_TLS_HOSTNAME_LEN || alpn_len > 1024 {
            return Err(TlsError::InvalidConfiguration);
        }
        let host = core::str::from_utf8(unsafe { slice::from_raw_parts(host, host_len) })
            .map_err(|_| TlsError::InvalidServerName)?;
        let bytes = unsafe { slice::from_raw_parts(alpn, alpn_len) };
        let mut protocols = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let size = usize::from(bytes[offset]);
            offset += 1;
            let end = offset
                .checked_add(size)
                .ok_or(TlsError::InvalidConfiguration)?;
            if size == 0 || end > bytes.len() || protocols.len() == 16 {
                return Err(TlsError::InvalidConfiguration);
            }
            protocols.push(bytes[offset..end].to_vec());
            offset = end;
        }
        #[cfg(feature = "test-fixtures")]
        let roots = tls::smoke_test_root_store()?;
        #[cfg(not(feature = "test-fixtures"))]
        let roots = tls::production_root_store();
        #[cfg(any(target_os = "mochios", target_os = "none"))]
        let time = Arc::new(tls::PlatformTimeProvider);
        #[cfg(not(any(target_os = "mochios", target_os = "none")))]
        let time = Arc::new(HostTime);
        let mut config = tls::build_client_config(roots, time)?;
        tls::set_client_alpn(&mut config, &protocols)?;
        Stream::new(Arc::new(config), host)
    };
    match create() {
        Ok(stream) => {
            unsafe { out.write(Box::into_raw(Box::new(stream))) };
            0
        }
        Err(error) => code(error),
    }
}

#[unsafe(no_mangle)]
unsafe extern "C" fn _mochi_tls_core_free(stream: *mut Stream) {
    drop(unsafe { Box::from_raw(stream) });
}
#[unsafe(no_mangle)]
unsafe extern "C" fn _mochi_tls_core_receive(
    stream: *mut Stream,
    bytes: *const u8,
    size: usize,
) -> c_int {
    result(unsafe { &mut *stream }.receive_tls(unsafe { slice::from_raw_parts(bytes, size) }))
}
#[unsafe(no_mangle)]
unsafe extern "C" fn _mochi_tls_core_write(
    stream: *mut Stream,
    bytes: *const u8,
    size: usize,
) -> c_int {
    result(unsafe { &mut *stream }.write(unsafe { slice::from_raw_parts(bytes, size) }))
}
#[unsafe(no_mangle)]
unsafe extern "C" fn _mochi_tls_core_close(stream: *mut Stream) -> c_int {
    result(unsafe { &mut *stream }.close_notify())
}
#[unsafe(no_mangle)]
unsafe extern "C" fn _mochi_tls_core_status(stream: *mut Stream, out: *mut Status) -> c_int {
    let stream = unsafe { &mut *stream };
    let state = match stream.state() {
        TlsState::Handshaking => 1,
        TlsState::Established => 2,
        TlsState::PeerClosed => 3,
        TlsState::Closing => 4,
        TlsState::Closed => 5,
        TlsState::Failed => 6,
    };
    unsafe {
        out.write(Status {
            state,
            receive: stream.plaintext().len() as u32,
            transmit: stream.ciphertext().len() as u32,
            protocol: stream
                .connection()
                .protocol_version()
                .map(u16::from)
                .unwrap_or(0),
            cipher: stream
                .connection()
                .cipher_suite()
                .map(u16::from)
                .unwrap_or(0),
        })
    };
    0
}
#[unsafe(no_mangle)]
unsafe extern "C" fn _mochi_tls_core_take(
    stream: *mut Stream,
    direction: c_int,
    out: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> c_int {
    let stream = unsafe { &mut *stream };
    let bytes = if direction == 0 {
        stream.ciphertext()
    } else {
        stream.plaintext()
    };
    let size = capacity.min(bytes.len());
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out, size);
        written.write(size)
    };
    result(if direction == 0 {
        stream.consume_ciphertext(size)
    } else {
        stream.consume_plaintext(size)
    })
}
#[unsafe(no_mangle)]
unsafe extern "C" fn _mochi_tls_core_info(
    stream: *mut Stream,
    field: u32,
    index: usize,
    out: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> c_int {
    let stream = unsafe { &mut *stream };
    if !matches!(
        stream.state(),
        TlsState::Established | TlsState::PeerClosed | TlsState::Closing | TlsState::Closed
    ) {
        return 14;
    }
    let info = || -> Result<Vec<u8>, TlsError> {
        let connection = stream.connection();
        match field {
            0 => Ok(connection.negotiated_protocol().unwrap_or(&[]).to_vec()),
            1 => connection
                .peer_certificates()
                .and_then(|chain| chain.get(index))
                .map(|c| c.as_ref().to_vec())
                .ok_or(TlsError::InvalidState),
            2 => Ok(connection.peer_certificate_info()?.subject.into_bytes()),
            3 => Ok(connection.peer_certificate_info()?.issuer.into_bytes()),
            4 => Ok(connection
                .peer_certificate_info()?
                .not_before
                .to_ne_bytes()
                .to_vec()),
            5 => Ok(connection
                .peer_certificate_info()?
                .not_after
                .to_ne_bytes()
                .to_vec()),
            _ => Err(TlsError::InvalidConfiguration),
        }
    };
    match info() {
        Ok(bytes) => {
            unsafe { written.write(bytes.len()) };
            if bytes.len() > capacity {
                return 11;
            }
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
            0
        }
        Err(e) => code(e),
    }
}
