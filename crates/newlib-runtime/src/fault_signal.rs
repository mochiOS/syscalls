use super::*;

fn signal_for_cause(cause: u64) -> Result<u32, c_int> {
    use syscall::MemoryFaultCause;
    match cause {
        value
            if value == MemoryFaultCause::Unmapped as u64
                || value == MemoryFaultCause::AccessDenied as u64
                || value == MemoryFaultCause::Unresolved as u64 =>
        {
            Ok(posix_protocol::SIGNAL_SEGV)
        }
        value
            if value == MemoryFaultCause::OutsideBacking as u64
                || value == MemoryFaultCause::BackingFailure as u64
                || value == MemoryFaultCause::ResourceUnavailable as u64 =>
        {
            Ok(posix_protocol::SIGNAL_BUS)
        }
        _ => Err(EINVAL),
    }
}

/// This runs on the native per-thread exception stack. Kernel-owned context
/// restoration retries the original instruction only after a handler returns.
pub(super) fn deliver(cause: u64) -> Result<(), c_int> {
    let signal = signal_for_cause(cause)?;
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
