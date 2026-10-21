//! Select and consume one-shot dispositions under the sigaction update lock.
use super::*;

pub(super) fn select(signal: u32) -> Result<SignalAction, c_int> {
    if signal == 0 || signal > posix_protocol::SIGNAL_MAX {
        return Err(EINVAL);
    }
    let _update = SIGNAL_ACTION_UPDATE.lock();
    let index = signal as usize - 1;
    let selected = SIGNAL_ACTIONS.lock()[index];
    // POSIX keeps SIGILL and SIGTRAP installed even with SA_RESETHAND.
    // Neither default nor ignored dispositions are catching functions.
    if selected.sa_flags & SA_RESETHAND != 0
        && selected.handler > 1
        && selected.handler != usize::MAX
        && signal != posix_protocol::SIGNAL_ILL
        && signal != posix_protocol::SIGNAL_TRAP
    {
        let child_options = if signal == posix_protocol::SIGNAL_CHLD {
            (if selected.sa_flags & SA_NOCLDSTOP != 0 {
                posix_protocol::SIGNAL_CHILD_OPTION_NOCLDSTOP
            } else {
                0
            }) | (if selected.sa_flags & SA_NOCLDWAIT != 0 {
                posix_protocol::SIGNAL_CHILD_OPTION_NOCLDWAIT
            } else {
                0
            })
        } else {
            0
        };
        posix_client()
            .map_err(map_posix_client_error)?
            .set_signal_disposition(posix_protocol::SignalDisposition {
                signal,
                kind: posix_protocol::SIGNAL_DISPOSITION_DEFAULT,
                child_options,
            })
            .map_err(map_posix_client_error)?;
        SIGNAL_ACTIONS.lock()[index] = SignalAction {
            handler: 0,
            sa_flags: selected.sa_flags & !SA_SIGINFO,
            ..selected
        };
    }
    // Release UPDATE before preparing or switching stacks, unmasking, or
    // invoking user code. The copied action retains this delivery's SIGINFO,
    // restart and mask settings, while later selections see the reset default.
    Ok(selected)
}
