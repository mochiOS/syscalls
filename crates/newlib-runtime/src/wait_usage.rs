//! Child CPU accounting is sampled by the same service transaction as wait.
use super::*;

#[unsafe(no_mangle)]
pub extern "C" fn wait(status: *mut c_int) -> c_int {
    waitpid(-1, status, 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn _wait(status: *mut c_int) -> c_int {
    wait(status)
}

#[unsafe(no_mangle)]
pub extern "C" fn wait3(status: *mut c_int, options: c_int, usage: *mut c_void) -> c_int {
    wait4(-1, status, options, usage)
}

#[unsafe(no_mangle)]
pub extern "C" fn wait4(
    pid: c_int,
    status: *mut c_int,
    options: c_int,
    usage: *mut c_void,
) -> c_int {
    if usage.is_null() {
        return waitpid(pid, status, options);
    }
    pthread_testcancel();
    let result = (|| {
        if options & !(WNOHANG | WUNTRACED | WCONTINUED) != 0 {
            return Err(EINVAL);
        }
        let (_, control) = register_current_thread().ok_or(EAGAIN)?;
        let caught = control.nonrestart_signal_generation.load(Ordering::Acquire);
        let client = posix_client().map_err(map_posix_client_error)?;
        let observation = loop {
            pthread_testcancel();
            if control.nonrestart_signal_generation.load(Ordering::Acquire) != caught {
                return Err(EINTR);
            }
            let epoch = client
                .thread_signal_epoch()
                .map_err(map_posix_client_error)?;
            pthread_testcancel();
            if control.nonrestart_signal_generation.load(Ordering::Acquire) != caught {
                return Err(EINTR);
            }
            match client.wait_child_usage_since(pid as i64, options as u32, epoch) {
                Ok(observation) => break observation,
                Err(PosixClientError::Remote(posix_protocol::STATUS_EINTR)) => {
                    drain_pending_signals()?
                }
                Err(error) => return Err(map_posix_client_error(error)),
            }
        };
        wait_usage_output::publish(observation, status, usage)
    })();
    if result.is_err() {
        pthread_testcancel();
    }
    result_with_errno(result, -1)
}
