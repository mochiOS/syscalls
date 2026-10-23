//! Process-local interpretation of authenticated signal metadata. A timer
//! cookie is never a C pointer. Snapshot the original sigval under STATE and
//! release the lock before changing dispositions, copying out, or invoking C.
use super::*;
use mochios_posix_client::{signal_context::InfoError, timer_value::ResolveError};

pub(super) enum Prepared {
    Origin(u32, posix_protocol::signal_origin::Origin),
    Ready(SigInfo),
}

fn error(error: InfoError) -> c_int {
    match error {
        InfoError::Overflow => EOVERFLOW,
        _ => EIO,
    }
}

impl Prepared {
    pub(super) fn into_info(self) -> Result<SigInfo, c_int> {
        match self {
            Self::Origin(signal, origin) => SigInfo::from_origin(signal, origin).map_err(error),
            Self::Ready(info) => Ok(info),
        }
    }
}

/// None is a deliberately discarded late timer notification, not a new
/// pending event or a protocol failure. POSIX leaves pending notification
/// treatment after timer_delete unspecified; we discard if deletion won the
/// local snapshot race. If snapshot won, its copied value remains deliverable.
pub(super) fn prepare(
    signal: u32,
    origin: posix_protocol::signal_origin::Origin,
) -> Result<Option<Prepared>, c_int> {
    if signal == 0 || signal > posix_protocol::SIGNAL_MAX {
        return Err(EIO);
    }
    if origin.source != posix_protocol::signal_origin::TIMER {
        // Plain handlers do not need conversion to narrow C pid_t/uid_t.
        // The transport has already validated this wire record.
        return Ok(Some(Prepared::Origin(signal, origin)));
    }
    // Validate the complete canonical record before treating any token as
    // retired. Malformed records must not be hidden by a stale-cookie check.
    let mut info = SigInfo::from_timer_origin(signal, origin, 0).map_err(error)?;
    let timer = origin.timer.ok_or(EIO)?;
    let resolved = state()
        .timer_values
        .resolve(timer.timer_id, timer.value_token);
    match resolved {
        Ok(value) => {
            info.si_value = mochios_posix_client::signal_context::SigValue { sival_ptr: value };
            Ok(Some(Prepared::Ready(info)))
        }
        Err(ResolveError::StaleToken) => Ok(None),
        // Unknown, unbound and wrong-timer cookies are not deletion races.
        Err(_) => Err(EIO),
    }
}
