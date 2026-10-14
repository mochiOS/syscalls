use super::*;

/// This runs on the native per-thread exception stack. Kernel-owned context
/// restoration retries the original instruction only after a handler returns.
pub(super) fn deliver(cause: u64, address: usize) -> Result<(), c_int> {
    let info = mochios_posix_client::signal_context::SigInfo::memory_fault(cause, address)
        .map_err(|_| EINVAL)?;
    let signal = info.si_signo as u32;
    let client = posix_client().map_err(map_posix_client_error)?;
    let fault = client
        .fault_signal_delivery(signal)
        .map_err(map_posix_client_error)?;
    // A mismatched reply must not run an unrelated handler or consume a token.
    if fault.signal.signal != signal {
        return Err(EIO);
    }
    if fault.disposition == posix_protocol::SIGNAL_DISPOSITION_CAUGHT {
        match dispatch_signal(signal as c_int)? {
            0 => {
                return client
                    .complete_signal_delivery(fault.signal)
                    .map_err(map_posix_client_error);
            }
            // A concurrent sigaction may have replaced the selected handler.
            // Never retry an unrepaired synchronous fault under SIG_IGN.
            1 | 3 => {}
            _ => return Err(EINVAL),
        }
    }
    client
        .report_process_signaled(fault.signal)
        .map_err(map_posix_client_error)?;
    process_exit(128 + signal as c_int)
}
