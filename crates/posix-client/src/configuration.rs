// Selector values from the SDK's sys/unistd.h; not native syscall selectors.
const SC_THREAD_KEYS_MAX: i32 = 38;
const SC_THREAD_THREADS_MAX: i32 = 40;
const SC_THREAD_DESTRUCTOR_ITERATIONS: i32 = 53;
const SC_IOV_MAX: i32 = 66;

/// Translate libc selectors using a validated native processor snapshot.
/// Unknown or inconsistent data is an error, never a fabricated single CPU.
pub fn processor_count(selector: i32, info: mnu_abi::ProcessorInfo) -> Result<u32, i32> {
    if !matches!(selector, 9 | 10) {
        return Err(-22);
    }
    if info.reserved != [0; 2] || info.online == 0 || info.online > info.configured {
        return Err(-5);
    }
    Ok(if selector == 9 {
        info.configured
    } else {
        info.online
    })
}

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
