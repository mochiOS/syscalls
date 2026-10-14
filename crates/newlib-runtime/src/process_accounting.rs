use super::*;
use mochios_posix_client::accounting::cpu_timeval;

/// The newlib SDK exposes the two POSIX CPU durations, not Linux's extended
/// rusage layout. Do not fabricate unmeasured RSS, fault or I/O counters.
#[repr(C)]
struct Rusage {
    ru_utime: Timeval,
    ru_stime: Timeval,
}

const _: () = {
    assert!(core::mem::size_of::<Rusage>() == 32);
    assert!(core::mem::align_of::<Rusage>() == 8);
    assert!(core::mem::offset_of!(Rusage, ru_stime) == 16);
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
        let (user, kernel, rate) = if who == 0 {
            // SELF has no process-shared POSIX policy to consult and also
            // works in a native bootstrap process without a POSIX endpoint.
            let usage =
                syscall::execution::usage(None).map_err(|error| map_kernel_errno(error.raw()))?;
            (
                u128::from(usage.user_ticks),
                u128::from(usage.kernel_ticks),
                usage.ticks_per_second,
            )
        } else {
            // Only waited children/descendants, owned by this authenticated
            // process. A client never supplies a PID or a foreign identity.
            let usage = posix_client()
                .map_err(map_posix_client_error)?
                .waited_child_cpu_usage()
                .map_err(map_posix_client_error)?;
            (usage.user_ticks, usage.kernel_ticks, usage.ticks_per_second)
        };
        let (user_seconds, user_microseconds) = cpu_timeval(user, rate)?;
        let (kernel_seconds, kernel_microseconds) = cpu_timeval(kernel, rate)?;
        let value = Rusage {
            ru_utime: Timeval {
                tv_sec: user_seconds,
                tv_usec: user_microseconds,
            },
            ru_stime: Timeval {
                tv_sec: kernel_seconds,
                tv_usec: kernel_microseconds,
            },
        };
        // No partial output if either counter or the service reply is invalid.
        unsafe {
            output.write(value);
        }
        Ok(0)
    })();
    result_with_errno(result, -1)
}
