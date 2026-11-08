//! Caller-only C access to the kernel's measured resident RAM snapshot.
use super::*;

#[unsafe(no_mangle)]
unsafe extern "C" fn mochios_process_memory_read(output: *mut u8, size: usize) -> c_int {
    let result = (|| {
        if size != 16 {
            return Err(EINVAL);
        }
        if output.is_null() {
            return Err(EFAULT);
        }
        let usage = syscall::execution::memory_usage(None)
            .map_err(|error| map_kernel_errno(error.raw()))?;
        let mut bytes = [0; 16];
        bytes[..8].copy_from_slice(&usage.current_bytes.to_ne_bytes());
        bytes[8..].copy_from_slice(&usage.peak_bytes.to_ne_bytes());
        user_copy::write(output, &bytes)?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}
