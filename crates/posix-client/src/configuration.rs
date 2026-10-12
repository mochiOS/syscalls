// Selector values from the SDK's sys/unistd.h; not native syscall selectors.
const SC_THREAD_KEYS_MAX: i32 = 38;
const SC_THREAD_THREADS_MAX: i32 = 40;
const SC_THREAD_DESTRUCTOR_ITERATIONS: i32 = 53;
const SC_IOV_MAX: i32 = 66;

/// Process-local limits exposed through newlib's sysconf selector ABI.
/// Return None for selectors requiring another source or not implemented here.
pub const fn local_limit(selector: i32) -> Option<usize> {
    match selector {
        2 => Some(crate::accounting::CLOCK_TICKS_PER_SECOND as usize), // _SC_CLK_TCK
        SC_THREAD_KEYS_MAX => Some(crate::thread::MAX_THREAD_KEYS),
        SC_THREAD_THREADS_MAX => Some(crate::thread::MAX_THREADS),
        SC_THREAD_DESTRUCTOR_ITERATIONS => Some(crate::thread::DESTRUCTOR_ITERATIONS),
        SC_IOV_MAX => Some(crate::io_vector::IOV_MAX),
        _ => None,
    }
}
