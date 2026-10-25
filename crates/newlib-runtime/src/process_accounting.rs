use super::*;

/// The mochiOS newlib ABI: two timeval values and a peak RSS value in KiB.
#[repr(C)]
struct Rusage {
    ru_utime: Timeval,
    ru_stime: Timeval,
    ru_maxrss: CLong,
}

const _: () = {
    assert!(core::mem::size_of::<Rusage>() == resource_usage_output::LEN);
    assert!(core::mem::align_of::<Rusage>() == 8);
    assert!(core::mem::offset_of!(Rusage, ru_stime) == 16);
    assert!(core::mem::offset_of!(Rusage, ru_maxrss) == 32);
};

#[unsafe(no_mangle)]
unsafe extern "C" fn getrusage(who: c_int, output: *mut Rusage) -> c_int {
    let result = (|| {
        if !matches!(who, 0 | -1) {
            return Err(EINVAL);
        }
        if output.is_null() {
            return Err(EFAULT);
        }
        let usage = if who == 0 {
            let cpu =
                syscall::execution::usage(None).map_err(|error| map_kernel_errno(error.raw()))?;
            let memory = syscall::execution::memory_usage(None)
                .map_err(|error| map_kernel_errno(error.raw()))?;
            if cpu.ticks_per_second == 0
                || cpu.reserved != 0
                || memory.current_bytes > memory.peak_bytes
            {
                return Err(EIO);
            }
            posix_protocol::wait_usage::Usage {
                cpu: posix_protocol::WaitedChildCpuUsage {
                    user_ticks: u128::from(cpu.user_ticks),
                    kernel_ticks: u128::from(cpu.kernel_ticks),
                    ticks_per_second: cpu.ticks_per_second,
                },
                peak_resident_bytes: memory.peak_bytes,
            }
        } else {
            posix_client()
                .map_err(map_posix_client_error)?
                .waited_child_usage()
                .map_err(map_posix_client_error)?
        };
        let bytes = resource_usage_output::encode(usage)?;
        user_copy::write(output.cast(), &bytes)?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}
