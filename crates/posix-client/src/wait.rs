//! POSIX waitid selectors and event descriptions, independent of native ABI.
use crate::newlib_errno::{EINVAL, EIO};
use mochios_posix_protocol as protocol;

pub const P_ALL: i32 = 0;
pub const P_PID: i32 = 1;
pub const P_PGID: i32 = 2;
pub const WEXITED: i32 = 4;
pub const WSTOPPED: i32 = 2;
pub const WNOWAIT: i32 = 16;

pub fn request(id_type: i32, id: u32, options: i32) -> Result<protocol::WaitRequest, i32> {
    const ALLOWED: i32 = 1 | WEXITED | WSTOPPED | 8 | WNOWAIT;
    if options & !ALLOWED != 0 || options & (WEXITED | WSTOPPED | 8) == 0 {
        return Err(EINVAL);
    }
    let selector = match id_type {
        P_ALL => -1,
        P_PID if id != 0 => i64::from(id),
        P_PGID => i64::from(id), // Zero selects the caller's current group.
        _ => return Err(EINVAL),
    };
    Ok(protocol::WaitRequest {
        selector,
        options: options as u32
            | protocol::WAIT_SELECT_EVENTS
            | if id_type == P_PGID {
                protocol::WAIT_SELECT_GROUP
            } else {
                0
            },
    })
}

pub fn origin(info: protocol::WaitInfo) -> Result<protocol::signal_origin::Origin, i32> {
    use protocol::signal_origin::*;
    let status = info.result.status;
    if status > 0xffff {
        return Err(EIO);
    }
    let child = if status == protocol::WAIT_STATUS_CONTINUED {
        ChildStatus {
            event: CONTINUED,
            status: protocol::SIGNAL_CONT,
        }
    } else if status & 0xff == 0x7f {
        ChildStatus {
            event: STOPPED,
            status: (status >> 8) & 0xff,
        }
    } else if status & 0x7f == 0 {
        ChildStatus {
            event: EXITED,
            status: (status >> 8) & 0xff,
        }
    } else if status & 0x7f < 0x7f {
        ChildStatus {
            event: if status & 0x80 == 0 { KILLED } else { DUMPED },
            status: status & 0x7f,
        }
    } else {
        return Err(EIO);
    };
    let origin = Origin {
        source: CHILD,
        process_id: info.result.process_id,
        real_uid: info.real_uid,
        child,
    };
    protocol::signal_origin::encode(origin, &mut [0; protocol::signal_origin::LEN])
        .map_err(|_| EIO)?;
    Ok(origin)
}
