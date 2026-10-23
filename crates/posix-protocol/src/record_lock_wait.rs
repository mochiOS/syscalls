//! One deferred lock call. Identity comes from native IPC, not this payload.
use crate::{ProtocolError, record_lock};

pub const LEN: usize = record_lock::REQUEST_LEN + 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub lock: record_lock::Request,
    pub epoch: u64,
}

pub fn encode(request: Request, out: &mut [u8]) -> Result<(), ProtocolError> {
    if !matches!(request.lock.operation, record_lock::Operation::Set(_)) {
        return Err(ProtocolError::InvalidLength);
    }
    let mut bytes = [0; LEN];
    record_lock::encode_request(request.lock, &mut bytes[..record_lock::REQUEST_LEN])?;
    bytes[record_lock::REQUEST_LEN..].copy_from_slice(&request.epoch.to_le_bytes());
    out.get_mut(..LEN)
        .ok_or(ProtocolError::BufferTooSmall)?
        .copy_from_slice(&bytes);
    Ok(())
}

pub fn decode(bytes: &[u8]) -> Result<Request, ProtocolError> {
    if bytes.len() != LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let lock = record_lock::decode_request(&bytes[..record_lock::REQUEST_LEN])?;
    if !matches!(lock.operation, record_lock::Operation::Set(_)) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(Request {
        lock,
        epoch: u64::from_le_bytes(bytes[record_lock::REQUEST_LEN..].try_into().unwrap()),
    })
}
