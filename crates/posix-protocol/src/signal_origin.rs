//! Signal provenance, not authority: all identities are recorded by the service.
use super::*;

pub const LEN: usize = 16;
pub const USER: u32 = 1;
pub const CHILD: u32 = 2;
pub const SYSTEM: u32 = 3;
pub const FAULT: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin {
    pub source: u32,
    pub real_uid: u32,
    pub process_id: u64,
}

impl Origin {
    pub const fn system() -> Self {
        Self {
            source: SYSTEM,
            real_uid: 0,
            process_id: 0,
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
    put_u32(output, 0, origin.source);
    put_u32(output, 4, origin.real_uid);
    put_u64(output, 8, origin.process_id);
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
    };
    encode(origin, &mut [0; LEN])?;
    Ok(origin)
}
