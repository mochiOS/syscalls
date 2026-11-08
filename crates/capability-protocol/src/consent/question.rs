//! Typed content shared by graphical and terminal presenters. An administrator
//! question cannot be confused with an ordinary capability Allow button.
use super::{
    Error,
    prompt::{self, Prompt},
};
use core::fmt;
const MAGIC: [u8; 8] = *b"MCNADM01";
const HEADER: usize = 24;
pub const MAX_DESCRIPTION: usize = 2048;
pub const MAX_BYTES: usize = HEADER + prompt::MAX_MESSAGE_BYTES + 32 + MAX_DESCRIPTION;
#[derive(Clone, Copy)]
pub struct Administrator<'a> {
    pub username: &'a str,
    pub description: &'a str,
}
pub struct Question<'a> {
    pub offer: Prompt<'a>,
    pub administrator: Option<Administrator<'a>>,
}
impl Question<'_> {
    pub fn write_text(&self, output: &mut impl fmt::Write) -> fmt::Result {
        if let Some(admin) = self.administrator {
            writeln!(output, "Administrator authentication required")?;
            writeln!(output, "{}", admin.description)?;
            writeln!(output, "Application: {}", self.offer.package)?;
            writeln!(output, "Enter the password for an administrator account.")
        } else {
            self.offer.write_text(output)
        }
    }
}
pub fn encode(
    offer: Prompt<'_>,
    administrator: Administrator<'_>,
    output: &mut [u8],
) -> Result<usize, Error> {
    if offer.choices.bits() != super::Choices::ONCE
        || administrator.username.len() > 32
        || administrator.description.is_empty()
        || administrator.description.len() > MAX_DESCRIPTION
        || administrator.username.chars().any(char::is_control)
        || administrator.description.chars().any(char::is_control)
    {
        return Err(Error::Invalid);
    }
    let mut encoded = [0; prompt::MAX_MESSAGE_BYTES];
    let length = prompt::encode(offer, &mut encoded)?;
    let total = HEADER + length + administrator.username.len() + administrator.description.len();
    let bytes = output.get_mut(..total).ok_or(Error::BufferTooSmall)?;
    bytes[..HEADER].fill(0);
    bytes[..8].copy_from_slice(&MAGIC);
    bytes[8..10].copy_from_slice(&1u16.to_le_bytes());
    bytes[10..12].copy_from_slice(&(administrator.username.len() as u16).to_le_bytes());
    bytes[12..14].copy_from_slice(&(administrator.description.len() as u16).to_le_bytes());
    bytes[16..20].copy_from_slice(&(length as u32).to_le_bytes());
    bytes[HEADER..HEADER + length].copy_from_slice(&encoded[..length]);
    bytes[HEADER + length..HEADER + length + administrator.username.len()]
        .copy_from_slice(administrator.username.as_bytes());
    bytes[HEADER + length + administrator.username.len()..]
        .copy_from_slice(administrator.description.as_bytes());
    Ok(total)
}
pub fn decode(bytes: &[u8]) -> Result<Question<'_>, Error> {
    if !bytes.starts_with(&MAGIC) {
        return Ok(Question {
            offer: prompt::decode(bytes)?,
            administrator: None,
        });
    }
    if bytes.len() < HEADER
        || bytes.len() > MAX_BYTES
        || bytes[8..10] != 1u16.to_le_bytes()
        || bytes[14..16] != [0; 2]
        || bytes[20..24] != [0; 4]
    {
        return Err(Error::Invalid);
    }
    let username = u16::from_le_bytes(bytes[10..12].try_into().unwrap()) as usize;
    let description = u16::from_le_bytes(bytes[12..14].try_into().unwrap()) as usize;
    let length = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
    if username > 32
        || description == 0
        || description > MAX_DESCRIPTION
        || length > prompt::MAX_MESSAGE_BYTES
        || bytes.len() != HEADER + length + username + description
    {
        return Err(Error::Invalid);
    }
    let username = core::str::from_utf8(&bytes[HEADER + length..HEADER + length + username])
        .map_err(|_| Error::Invalid)?;
    let description = core::str::from_utf8(&bytes[HEADER + length + username.len()..])
        .map_err(|_| Error::Invalid)?;
    if username.chars().any(char::is_control) || description.chars().any(char::is_control) {
        return Err(Error::Invalid);
    }
    let offer = prompt::decode(&bytes[HEADER..HEADER + length])?;
    if offer.choices.bits() != super::Choices::ONCE {
        return Err(Error::Invalid);
    }
    Ok(Question {
        offer,
        administrator: Some(Administrator {
            username,
            description,
        }),
    })
}
