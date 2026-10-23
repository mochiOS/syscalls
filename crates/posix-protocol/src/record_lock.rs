//! Process-owned record lock messages. The file must be selected by an explicit
//! FileHandle attachment, and the owner by authenticated IPC sender identity.
//! No pathname, FD, inode, process identifier or executable address is accepted
//! in a request.
use crate::ProtocolError;

pub const REQUEST_LEN: usize = 32;
pub const REPLY_LEN: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Query(Kind),
    Set(Kind),
    Unlock,
    /// Closing any descriptor of a file releases all of this owner's locks.
    ReleaseFile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Start,
    Current,
    End,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub operation: Operation,
    pub origin: Origin,
    pub start: i64,
    pub length: i64,
}

/// FileHandle authority, independent of claimed access modes or POSIX UID.
/// Query/unlock/release need no data access; setting requires the matching
/// delegated data right. SEEK_CUR snapshots require seek authority as well.
pub fn required_rights(request: Request) -> u64 {
    mnu_abi::HANDLE_RIGHT_TRANSFER
        | match request.operation {
            Operation::Set(Kind::Read) => mnu_abi::HANDLE_RIGHT_READ,
            Operation::Set(Kind::Write) => mnu_abi::HANDLE_RIGHT_WRITE,
            _ => 0,
        }
        | if request.origin == Origin::Current {
            mnu_abi::HANDLE_RIGHT_SEEK
        } else {
            0
        }
}

/// Query replies use a canonical absolute range. Zero length includes future
/// growth. `Unlocked` must leave the caller's other flock fields unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    Done,
    Unlocked,
    Conflict {
        owner: u64,
        kind: Kind,
        start: i64,
        length: i64,
    },
}

fn kind_byte(kind: Kind) -> u8 {
    match kind {
        Kind::Read => 1,
        Kind::Write => 2,
    }
}

fn decode_kind(byte: u8) -> Result<Kind, ProtocolError> {
    match byte {
        1 => Ok(Kind::Read),
        2 => Ok(Kind::Write),
        _ => Err(ProtocolError::InvalidLength),
    }
}

pub fn encode_request(request: Request, out: &mut [u8]) -> Result<(), ProtocolError> {
    let (operation, kind) = match request.operation {
        Operation::Query(kind) => (1, kind_byte(kind)),
        Operation::Set(kind) => (2, kind_byte(kind)),
        Operation::Unlock => (3, 0),
        Operation::ReleaseFile => {
            if request.origin != Origin::Start || request.start != 0 || request.length != 0 {
                return Err(ProtocolError::InvalidLength);
            }
            (4, 0)
        }
    };
    let out = out
        .get_mut(..REQUEST_LEN)
        .ok_or(ProtocolError::BufferTooSmall)?;
    out.fill(0);
    out[0] = 1;
    out[1] = operation;
    out[2] = kind;
    out[3] = match request.origin {
        Origin::Start => 0,
        Origin::Current => 1,
        Origin::End => 2,
    };
    out[8..16].copy_from_slice(&request.start.to_le_bytes());
    out[16..24].copy_from_slice(&request.length.to_le_bytes());
    Ok(())
}

pub fn decode_request(bytes: &[u8]) -> Result<Request, ProtocolError> {
    if bytes.len() != REQUEST_LEN
        || bytes[0] != 1
        || bytes[4..8] != [0; 4]
        || bytes[24..32] != [0; 8]
    {
        return Err(ProtocolError::InvalidLength);
    }
    let operation = match (bytes[1], bytes[2]) {
        (1, kind) => Operation::Query(decode_kind(kind)?),
        (2, kind) => Operation::Set(decode_kind(kind)?),
        (3, 0) => Operation::Unlock,
        (4, 0) => Operation::ReleaseFile,
        _ => return Err(ProtocolError::InvalidLength),
    };
    let origin = match bytes[3] {
        0 => Origin::Start,
        1 => Origin::Current,
        2 => Origin::End,
        _ => return Err(ProtocolError::InvalidLength),
    };
    let request = Request {
        operation,
        origin,
        start: i64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        length: i64::from_le_bytes(bytes[16..24].try_into().unwrap()),
    };
    if operation == Operation::ReleaseFile
        && (origin != Origin::Start || request.start != 0 || request.length != 0)
    {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(request)
}

pub fn encode_reply(reply: Reply, out: &mut [u8]) -> Result<(), ProtocolError> {
    if let Reply::Conflict {
        owner,
        start,
        length,
        ..
    } = reply
    {
        // Canonical replies cannot have negative lengths. END == MAX + 1 is
        // valid and also represents the infinite endpoint in the service.
        if owner == 0
            || start < 0
            || length < 0
            || i128::from(start) + i128::from(length) > i128::from(i64::MAX) + 1
        {
            return Err(ProtocolError::InvalidLength);
        }
    }
    let out = out
        .get_mut(..REPLY_LEN)
        .ok_or(ProtocolError::BufferTooSmall)?;
    out.fill(0);
    out[0] = 1;
    match reply {
        Reply::Done => {}
        Reply::Unlocked => out[1] = 1,
        Reply::Conflict {
            owner,
            kind,
            start,
            length,
        } => {
            out[1] = 2;
            out[2] = kind_byte(kind);
            out[8..16].copy_from_slice(&owner.to_le_bytes());
            out[16..24].copy_from_slice(&start.to_le_bytes());
            out[24..32].copy_from_slice(&length.to_le_bytes());
        }
    }
    Ok(())
}

pub fn decode_reply(bytes: &[u8]) -> Result<Reply, ProtocolError> {
    if bytes.len() != REPLY_LEN || bytes[0] != 1 || bytes[3..8] != [0; 5] {
        return Err(ProtocolError::InvalidLength);
    }
    let reply = match bytes[1] {
        0 | 1 if bytes[2] == 0 && bytes[8..32] == [0; 24] => {
            if bytes[1] == 0 {
                Reply::Done
            } else {
                Reply::Unlocked
            }
        }
        2 => Reply::Conflict {
            owner: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            kind: decode_kind(bytes[2])?,
            start: i64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            length: i64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        },
        _ => return Err(ProtocolError::InvalidLength),
    };
    encode_reply(reply, &mut [0; REPLY_LEN])?;
    Ok(reply)
}
