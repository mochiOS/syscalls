//! Bounded, NUL-terminated slave pathname returned by an existing master.
//! A pathname is information, never replacement Handle authority.
use crate::ProtocolError;

pub const MAX_LEN: usize = 64;
const PREFIX: &[u8] = b"/dev/pts/";

fn valid(component: &[u8]) -> bool {
    !component.is_empty()
        && component.len() + PREFIX.len() < MAX_LEN
        && component != b"."
        && component != b".."
        && !component.contains(&0)
        && !component.contains(&b'/')
}

pub fn encode(component: &[u8], output: &mut [u8]) -> Result<usize, ProtocolError> {
    if !valid(component) {
        return Err(ProtocolError::InvalidLength);
    }
    let length = PREFIX.len() + component.len() + 1;
    if output.len() < length {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..PREFIX.len()].copy_from_slice(PREFIX);
    output[PREFIX.len()..length - 1].copy_from_slice(component);
    output[length - 1] = 0;
    Ok(length)
}

/// Validate the entire reply; return the pathname without its final NUL.
pub fn decode(input: &[u8]) -> Result<&[u8], ProtocolError> {
    if input.len() > MAX_LEN || input.last() != Some(&0) || !input.starts_with(PREFIX) {
        return Err(ProtocolError::InvalidLength);
    }
    let component = input
        .get(PREFIX.len()..input.len() - 1)
        .ok_or(ProtocolError::InvalidLength)?;
    if !valid(component) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(&input[..input.len() - 1])
}
