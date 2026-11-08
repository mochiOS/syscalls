//! Requests and credentials for one broker-owned administrator operation.
use crate::consent::{self, Correlation, frontend};
pub const OPERATION_OPCODE: u32 = u32::from_le_bytes(*b"ADM1");
pub const RUN_OPCODE: u32 = u32::from_le_bytes(*b"ADR1");
pub const AUTHENTICATE_OPCODE: u32 = u32::from_le_bytes(*b"ADP1");
pub const MAX_OPERATION: usize = 4128;
pub const MAX_CREDENTIAL_BYTES: usize = 76 + 32 + 1024;
pub const HEADER: usize = 8;
pub fn encode_operation(operation: &[u8], output: &mut [u8]) -> Result<usize, consent::Error> {
    if operation.is_empty() || operation.len() > MAX_OPERATION {
        return Err(consent::Error::Invalid);
    }
    let bytes = output
        .get_mut(..HEADER + operation.len())
        .ok_or(consent::Error::BufferTooSmall)?;
    bytes[..4].copy_from_slice(&OPERATION_OPCODE.to_le_bytes());
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    bytes[8..].copy_from_slice(operation);
    Ok(bytes.len())
}
pub fn decode_operation(bytes: &[u8]) -> Result<&[u8], consent::Error> {
    if bytes.len() <= HEADER
        || bytes.len() > HEADER + MAX_OPERATION
        || bytes[..4] != OPERATION_OPCODE.to_le_bytes()
        || bytes[4..8] != 1u32.to_le_bytes()
    {
        return Err(consent::Error::Invalid);
    }
    Ok(&bytes[8..])
}
pub struct Credentials<'a> {
    pub correlation: Correlation,
    pub name: &'a str,
    pub password: &'a [u8],
}
pub fn encode_credentials(
    credentials: Credentials<'_>,
    output: &mut [u8],
) -> Result<usize, consent::Error> {
    let command = frontend::encode(
        credentials.correlation,
        frontend::Action::Decide(consent::Choice::AllowOnce),
    )?;
    if credentials.name.is_empty()
        || credentials.name.len() > 32
        || credentials.name.as_bytes().contains(&0)
        || credentials.password.len() > 1024
    {
        return Err(consent::Error::Invalid);
    }
    let length = 76 + credentials.name.len() + credentials.password.len();
    let bytes = output
        .get_mut(..length)
        .ok_or(consent::Error::BufferTooSmall)?;
    bytes[..4].copy_from_slice(&AUTHENTICATE_OPCODE.to_le_bytes());
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    bytes[8..72].copy_from_slice(&command);
    bytes[72..74].copy_from_slice(&(credentials.name.len() as u16).to_le_bytes());
    bytes[74..76].copy_from_slice(&(credentials.password.len() as u16).to_le_bytes());
    bytes[76..76 + credentials.name.len()].copy_from_slice(credentials.name.as_bytes());
    bytes[76 + credentials.name.len()..].copy_from_slice(credentials.password);
    Ok(length)
}
pub fn decode_credentials(bytes: &[u8]) -> Result<Credentials<'_>, consent::Error> {
    if bytes.len() < 76
        || bytes.len() > MAX_CREDENTIAL_BYTES
        || bytes[..4] != AUTHENTICATE_OPCODE.to_le_bytes()
        || bytes[4..8] != 1u32.to_le_bytes()
    {
        return Err(consent::Error::Invalid);
    }
    let (correlation, action) = frontend::decode(&bytes[8..72])?;
    if action != frontend::Action::Decide(consent::Choice::AllowOnce) {
        return Err(consent::Error::Invalid);
    }
    let name = u16::from_le_bytes(bytes[72..74].try_into().unwrap()) as usize;
    let password = u16::from_le_bytes(bytes[74..76].try_into().unwrap()) as usize;
    if name == 0 || name > 32 || password > 1024 || bytes.len() != 76 + name + password {
        return Err(consent::Error::Invalid);
    }
    let name = core::str::from_utf8(&bytes[76..76 + name]).map_err(|_| consent::Error::Invalid)?;
    if name.as_bytes().contains(&0) {
        return Err(consent::Error::Invalid);
    }
    Ok(Credentials {
        correlation,
        name,
        password: &bytes[76 + name.len()..],
    })
}

/// Typed compound operation: one approval for creating a managed account and
/// setting its initial password. Each nested frame retains its own request ID.
pub const CREATE_ACCOUNT: [u8; 4] = *b"ACR1";
pub const AUTO_LOGIN: [u8; 4] = *b"ALG1";
pub fn encode_create_account(
    add: &[u8],
    password: &[u8],
    output: &mut [u8],
) -> Result<usize, consent::Error> {
    let length = 8usize
        .checked_add(add.len())
        .and_then(|n| n.checked_add(password.len()))
        .ok_or(consent::Error::Invalid)?;
    if add.is_empty() || password.is_empty() || length > MAX_OPERATION {
        return Err(consent::Error::Invalid);
    }
    let output = output
        .get_mut(..length)
        .ok_or(consent::Error::BufferTooSmall)?;
    output[..4].copy_from_slice(&CREATE_ACCOUNT);
    output[4..8].copy_from_slice(&(add.len() as u32).to_le_bytes());
    output[8..8 + add.len()].copy_from_slice(add);
    output[8 + add.len()..].copy_from_slice(password);
    Ok(length)
}
pub fn decode_create_account(input: &[u8]) -> Result<(&[u8], &[u8]), consent::Error> {
    if input.len() < 8 || input.len() > MAX_OPERATION || !input.starts_with(&CREATE_ACCOUNT) {
        return Err(consent::Error::Invalid);
    }
    let length = u32::from_le_bytes(input[4..8].try_into().unwrap()) as usize;
    let rest = &input[8..];
    if length == 0 || length >= rest.len() {
        return Err(consent::Error::Invalid);
    }
    Ok(rest.split_at(length))
}
pub fn encode_auto_login(
    enabled: bool,
    username: &str,
    output: &mut [u8],
) -> Result<usize, consent::Error> {
    if username.len() > 32
        || username.chars().any(char::is_control)
        || username.as_bytes().contains(&0)
    {
        return Err(consent::Error::Invalid);
    }
    let output = output
        .get_mut(..5 + username.len())
        .ok_or(consent::Error::BufferTooSmall)?;
    output[..4].copy_from_slice(&AUTO_LOGIN);
    output[4] = u8::from(enabled);
    output[5..].copy_from_slice(username.as_bytes());
    Ok(output.len())
}
pub fn decode_auto_login(input: &[u8]) -> Result<(bool, &str), consent::Error> {
    if input.len() < 5 || input.len() > 37 || !input.starts_with(&AUTO_LOGIN) || input[4] > 1 {
        return Err(consent::Error::Invalid);
    }
    let name = core::str::from_utf8(&input[5..]).map_err(|_| consent::Error::Invalid)?;
    if name.chars().any(char::is_control) || name.as_bytes().contains(&0) {
        return Err(consent::Error::Invalid);
    }
    Ok((input[4] != 0, name))
}
