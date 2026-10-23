//! Only an owner-bound preparation token is wire data. File identity and image
//! generations come from delegated FileHandles and trusted native observations.
use crate::ProtocolError;

pub const LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    /// Zero starts a preparation; nonzero appends a batch to that preparation.
    Prepare(u64),
    Cancel(u64),
}

pub fn encode(request: Request, out: &mut [u8]) -> Result<(), ProtocolError> {
    let (operation, token) = match request {
        Request::Prepare(token) => (1, token),
        Request::Cancel(0) => return Err(ProtocolError::InvalidLength),
        Request::Cancel(token) => (2, token),
    };
    let out = out.get_mut(..LEN).ok_or(ProtocolError::BufferTooSmall)?;
    out.fill(0);
    out[0] = 1;
    out[1] = operation;
    out[8..16].copy_from_slice(&token.to_le_bytes());
    Ok(())
}

pub fn decode(bytes: &[u8]) -> Result<Request, ProtocolError> {
    if bytes.len() != LEN || bytes[0] != 1 || bytes[2..8] != [0; 6] {
        return Err(ProtocolError::InvalidLength);
    }
    let token = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    match bytes[1] {
        1 => Ok(Request::Prepare(token)),
        2 if token != 0 => Ok(Request::Cancel(token)),
        _ => Err(ProtocolError::InvalidLength),
    }
}

/// Zero means no locked file in an initial batch, or successful cancellation.
pub fn encode_reply(token: u64, out: &mut [u8]) -> Result<(), ProtocolError> {
    let out = out.get_mut(..LEN).ok_or(ProtocolError::BufferTooSmall)?;
    out.fill(0);
    out[0] = 1;
    out[8..16].copy_from_slice(&token.to_le_bytes());
    Ok(())
}

pub fn decode_reply(bytes: &[u8]) -> Result<u64, ProtocolError> {
    if bytes.len() != LEN || bytes[0] != 1 || bytes[1..8] != [0; 7] {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(u64::from_le_bytes(bytes[8..16].try_into().unwrap()))
}
