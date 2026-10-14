use super::*;

/// This runs on the native per-thread exception stack. Kernel-owned context
/// restoration retries the original instruction only after a handler returns.
pub(super) fn deliver(cause: u64, address: usize, context: &mut UContext) -> Result<(), c_int> {
    let info = mochios_posix_client::signal_context::SigInfo::memory_fault(cause, address)
        .map_err(|_| EINVAL)?;
    let signal = info.si_signo as u32;
    let (_, control) = register_current_thread().ok_or(EAGAIN)?;
    let client = posix_client().map_err(map_posix_client_error)?;
    loop {
        let mut preparation = Preparation::new(control)?;
        let epoch = preparation.epoch;
        let received = client
            .fault_signal_delivery(signal)
            .map_err(map_posix_client_error);
        if FORK_EPOCH.load(Ordering::Acquire) != epoch {
            continue;
        }
        let fault = received?;
        // A mismatched reply must not run an unrelated handler or consume a token.
        if fault.signal.signal != signal {
            return Err(EIO);
        }
        if fault.disposition == posix_protocol::SIGNAL_DISPOSITION_CAUGHT {
            let dispatched =
                dispatch_signal(fault.signal, Some(info), context, true, &mut preparation);
            if FORK_EPOCH.load(Ordering::Acquire) != epoch {
                if !preparation.started() {
                    continue;
                }
                // The copied handler may repair its child context, but cannot
                // consume the parent's still-authenticated fault delivery.
                return dispatched
                    .and_then(|result| if result == 0 { Ok(()) } else { Err(EINVAL) });
            }
            match dispatched {
                Ok(0) => {
                    let finished = client
                        .complete_signal_delivery(fault.signal)
                        .map_err(map_posix_client_error);
                    // The repaired context is already copied. A child must not
                    // inherit a parent's completion error or complete it again.
                    return if FORK_EPOCH.load(Ordering::Acquire) != epoch {
                        Ok(())
                    } else {
                        finished
                    };
                }
                // A concurrent sigaction may have replaced the selected handler.
                // Never retry an unrepaired synchronous fault under SIG_IGN.
                Ok(1 | 3) => {}
                result => {
                    let _ = client.complete_signal_delivery(fault.signal);
                    if FORK_EPOCH.load(Ordering::Acquire) != epoch {
                        continue;
                    }
                    return Err(result.err().unwrap_or(EINVAL));
                }
            }
        }
        let reported = client
            .report_process_signaled(fault.signal)
            .map_err(map_posix_client_error);
        if FORK_EPOCH.load(Ordering::Acquire) != epoch {
            continue;
        }
        reported?;
        process_exit(128 + signal as c_int)
    }
}
