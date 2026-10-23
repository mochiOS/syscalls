//! Read-only limits of an existing terminal object. All fields are userspace
//! provider data; the kernel forwards the selector and bytes without parsing.
use crate::ProtocolError;

pub const RESPONSE_LEN: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum canonical line bytes, including its terminating delimiter.
    pub canonical_bytes: u32,
    /// Maximum queued input bytes, including an unfinished canonical line.
    pub input_bytes: u32,
    /// Control character value that disables a terminal special character.
    pub disabled_character: u8,
}

impl Limits {
    pub fn encode(self) -> [u8; RESPONSE_LEN] {
        let mut output = [0; RESPONSE_LEN];
        output[..4].copy_from_slice(&self.canonical_bytes.to_le_bytes());
        output[4..8].copy_from_slice(&self.input_bytes.to_le_bytes());
        output[8] = self.disabled_character;
        output
    }

    /// Reject truncated/extended replies, reserved bytes and impossible bounds.
    pub fn decode(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.len() != RESPONSE_LEN || input[9..] != [0; 3] {
            return Err(ProtocolError::InvalidLength);
        }
        let value = Self {
            canonical_bytes: u32::from_le_bytes(input[..4].try_into().unwrap()),
            input_bytes: u32::from_le_bytes(input[4..8].try_into().unwrap()),
            disabled_character: input[8],
        };
        if value.canonical_bytes == 0 || value.canonical_bytes > value.input_bytes {
            return Err(ProtocolError::InvalidLength);
        }
        Ok(value)
    }
}
