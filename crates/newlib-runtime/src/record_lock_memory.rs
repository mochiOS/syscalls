//! Application flock memory stops at this boundary; the IPC carries values.
use super::*;
use posix_protocol::record_lock::{Kind, Operation, Origin, Reply, Request};

#[repr(C)]
pub(super) struct Flock {
    kind: i16,
    origin: i16,
    start: i64,
    length: i64,
    pid: c_int,
    reserved: i16,
}

pub(super) fn read_request(command: c_int, input: *mut Flock) -> Result<Request, c_int> {
    let mut bytes = [0; core::mem::size_of::<Flock>()];
    user_copy::read(input.cast(), &mut bytes)?;
    let kind = i16::from_ne_bytes(bytes[0..2].try_into().unwrap());
    let origin = match i16::from_ne_bytes(bytes[2..4].try_into().unwrap()) {
        0 => Origin::Start,
        1 => Origin::Current,
        2 => Origin::End,
        _ => return Err(EINVAL),
    };
    let operation = match (command, kind) {
        (F_GETLK, 1) => Operation::Query(Kind::Read),
        (F_GETLK, 2) => Operation::Query(Kind::Write),
        (F_SETLK | F_SETLKW, 1) => Operation::Set(Kind::Read),
        (F_SETLK | F_SETLKW, 2) => Operation::Set(Kind::Write),
        (F_SETLK | F_SETLKW, 3) => Operation::Unlock,
        _ => return Err(EINVAL),
    };
    Ok(Request {
        operation,
        origin,
        start: i64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
        length: i64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
    })
}

pub(super) fn write_reply(output: *mut Flock, reply: Reply) -> Result<(), c_int> {
    match reply {
        Reply::Unlocked => user_copy::write(output.cast(), &3i16.to_ne_bytes()),
        Reply::Conflict {
            owner,
            kind,
            start,
            length,
        } => {
            let pid = c_int::try_from(owner).map_err(|_| EOVERFLOW)?;
            let mut bytes = [0; core::mem::size_of::<Flock>()];
            let kind = if kind == Kind::Read { 1i16 } else { 2i16 };
            bytes[..2].copy_from_slice(&kind.to_ne_bytes());
            bytes[8..16].copy_from_slice(&start.to_ne_bytes());
            bytes[16..24].copy_from_slice(&length.to_ne_bytes());
            bytes[24..28].copy_from_slice(&pid.to_ne_bytes());
            user_copy::write(output.cast(), &bytes)
        }
        Reply::Done => Err(EIO),
    }
}
