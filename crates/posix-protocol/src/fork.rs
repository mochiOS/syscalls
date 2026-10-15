//! Opaque service-local tokens, never process IDs, native Handles or pointers.
use crate::ProtocolError;
pub const TOKEN_LEN: usize = 8;

pub fn encode_token(token: u64, output: &mut [u8]) -> Result<(), ProtocolError> {
    if token == 0 || output.len() != TOKEN_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    output.copy_from_slice(&token.to_le_bytes());
    Ok(())
}

pub fn decode_token(input: &[u8]) -> Result<u64, ProtocolError> {
    let token = u64::from_le_bytes(input.try_into().map_err(|_| ProtocolError::InvalidLength)?);
    if token == 0 {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(token)
}
