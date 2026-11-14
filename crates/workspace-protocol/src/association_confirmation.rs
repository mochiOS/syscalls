//! OS-owned default-application confirmation. The token correlates a pending
//! transaction; the service also authenticates its exact presenter process.
use crate::ProtocolError;
pub const PREFIX: usize = 24;
pub const MAX_DESCRIPTION: usize = 2048;
pub fn encode(
    token: [u8; 16],
    description: &str,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    if description.is_empty()
        || description.len() > MAX_DESCRIPTION
        || description.chars().any(|c| {
            c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
    {
        return Err(ProtocolError::InvalidField);
    }
    let size = PREFIX + description.len();
    let bytes = output.get_mut(..size).ok_or(ProtocolError::InvalidLength)?;
    bytes[..PREFIX].fill(0);
    bytes[..16].copy_from_slice(&token);
    bytes[16..18].copy_from_slice(&(description.len() as u16).to_le_bytes());
    bytes[PREFIX..].copy_from_slice(description.as_bytes());
    Ok(size)
}
pub fn decode(bytes: &[u8]) -> Result<([u8; 16], &str), ProtocolError> {
    if bytes.len() < PREFIX || bytes[18..PREFIX] != [0; 6] {
        return Err(ProtocolError::InvalidLength);
    }
    let size = u16::from_le_bytes(bytes[16..18].try_into().unwrap()) as usize;
    if bytes.len() != PREFIX + size {
        return Err(ProtocolError::InvalidLength);
    }
    let description =
        core::str::from_utf8(&bytes[PREFIX..]).map_err(|_| ProtocolError::InvalidField)?;
    if description.is_empty()
        || size > MAX_DESCRIPTION
        || description.chars().any(|c| {
            c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
    {
        return Err(ProtocolError::InvalidField);
    }
    Ok((bytes[..16].try_into().unwrap(), description))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prompts_are_bounded_exact_and_cannot_inject_control_text() {
        let mut bytes = [0; PREFIX + MAX_DESCRIPTION];
        let n = encode([7; 16], "Use Editor for text/plain?", &mut bytes).unwrap();
        assert_eq!(
            decode(&bytes[..n]).unwrap(),
            ([7; 16], "Use Editor for text/plain?")
        );
        assert!(decode(&bytes[..n - 1]).is_err());
        assert!(decode(&bytes[..n + 1]).is_err());
        bytes[18] = 1;
        assert!(decode(&bytes[..n]).is_err());
        bytes[18] = 0;
        bytes[PREFIX] = 0xff;
        assert!(decode(&bytes[..n]).is_err());
        for text in [
            "",
            "app\nChange Default",
            "app\u{202e}exe",
            "app\u{2066}name",
        ] {
            assert!(encode([0; 16], text, &mut bytes).is_err());
        }
    }
}
