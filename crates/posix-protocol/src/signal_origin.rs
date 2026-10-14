//! Signal provenance, not authority: all identities are recorded by the service.
use super::*;

pub const LEN: usize = 24;
pub const USER: u32 = 1;
pub const CHILD: u32 = 2;
pub const SYSTEM: u32 = 3;
pub const FAULT: u32 = 4;
pub const EXITED: u32 = 1;
pub const KILLED: u32 = 2;
pub const DUMPED: u32 = 3;
pub const TRAPPED: u32 = 4;
pub const STOPPED: u32 = 5;
pub const CONTINUED: u32 = 6;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChildStatus {
    pub event: u32,
    pub status: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    pub source: u32,
    pub real_uid: u32,
    pub process_id: u64,
    pub child: ChildStatus,
}

impl Origin {
    pub const fn system() -> Self {
        Self {
            source: SYSTEM,
            real_uid: 0,
            process_id: 0,
            child: ChildStatus {
                event: 0,
                status: 0,
            },
        }
    }
}

pub fn encode(origin: Origin, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if !matches!(origin.source, USER | CHILD | SYSTEM | FAULT)
        || (matches!(origin.source, USER | CHILD) && origin.process_id == 0)
        || (matches!(origin.source, SYSTEM | FAULT)
            && (origin.process_id != 0 || origin.real_uid != 0))
    {
        return Err(ProtocolError::InvalidLength);
    }
    if origin.source == CHILD {
        let valid = match origin.child.event {
            EXITED => origin.child.status <= 255,
            KILLED | DUMPED | TRAPPED | STOPPED => (1..=SIGNAL_MAX).contains(&origin.child.status),
            CONTINUED => origin.child.status == SIGNAL_CONT,
            _ => false,
        };
        if !valid {
            return Err(ProtocolError::InvalidLength);
        }
    } else if origin.child != ChildStatus::default() {
        return Err(ProtocolError::InvalidLength);
    }
    put_u32(output, 0, origin.source);
    put_u32(output, 4, origin.real_uid);
    put_u64(output, 8, origin.process_id);
    put_u32(output, 16, origin.child.event);
    put_u32(output, 20, origin.child.status);
    Ok(())
}

pub fn decode(input: &[u8]) -> Result<Origin, ProtocolError> {
    if input.len() != LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let origin = Origin {
        source: get_u32(input, 0),
        real_uid: get_u32(input, 4),
        process_id: get_u64(input, 8),
        child: ChildStatus {
            event: get_u32(input, 16),
            status: get_u32(input, 20),
        },
    };
    encode(origin, &mut [0; LEN])?;
    Ok(origin)
}
