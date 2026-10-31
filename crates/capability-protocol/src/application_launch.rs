//! Verified application launch. Four explicit IPC attachments carry the
//! caller's read scope and the three stdio objects; no Handle labels or PID
//! are serialized. POSIX descriptor metadata remains opaque to this codec.
use crate::ProtocolError as Error;

pub const OPCODE: u32 = u32::from_le_bytes(*b"MAL1");
pub const VERSION: u32 = 1;
pub const HEADER_BYTES: usize = 40;
pub const MAX_BYTES: usize = 1024;
pub const MAX_ITEMS: usize = 64;

pub struct Request<'a> {
    pub path: &'a str,
    /// Complete argv, including argv[0]. Empty argument strings are valid.
    pub arguments: &'a [&'a str],
    pub environment: &'a [&'a str],
    pub stdio_metadata: [u64; 3],
}

#[derive(Clone, Copy, Debug)]
pub struct Strings<'a> {
    bytes: &'a [u8],
    count: usize,
}
impl<'a> Strings<'a> {
    pub fn iter(self) -> impl Iterator<Item = &'a str> {
        self.bytes
            .split(|byte| *byte == 0)
            .take(self.count)
            .map(|bytes| core::str::from_utf8(bytes).expect("validated text"))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Decoded<'a> {
    pub path: &'a str,
    pub arguments: Strings<'a>,
    pub environment: Strings<'a>,
    pub stdio_metadata: [u64; 3],
}

fn path(text: &str) -> Result<(), Error> {
    if !text.starts_with('/') || text.len() > crate::MAX_EXECUTABLE_PATH_LEN {
        return Err(Error::InvalidField);
    }
    valid_text(text)
}
fn valid_text(text: &str) -> Result<(), Error> {
    if text.as_bytes().contains(&0) {
        return Err(Error::InvalidField);
    }
    Ok(())
}
fn environment(text: &str) -> Result<(), Error> {
    valid_text(text)?;
    if text.split_once('=').is_none_or(|(name, _)| name.is_empty()) {
        return Err(Error::InvalidField);
    }
    Ok(())
}

pub fn encode(request: &Request<'_>, output: &mut [u8]) -> Result<usize, Error> {
    path(request.path)?;
    if request.arguments.is_empty()
        || request
            .arguments
            .len()
            .saturating_add(request.environment.len())
            > MAX_ITEMS
    {
        return Err(Error::InvalidLength);
    }
    let mut length = HEADER_BYTES + request.path.len() + 1;
    for text in request.arguments {
        valid_text(text)?;
        length = length
            .checked_add(text.len() + 1)
            .ok_or(Error::InvalidLength)?;
    }
    for text in request.environment {
        environment(text)?;
        length = length
            .checked_add(text.len() + 1)
            .ok_or(Error::InvalidLength)?;
    }
    if length > MAX_BYTES || length > output.len() {
        return Err(Error::InvalidLength);
    }
    output[..HEADER_BYTES].fill(0);
    output[..4].copy_from_slice(&OPCODE.to_le_bytes());
    output[4..8].copy_from_slice(&VERSION.to_le_bytes());
    output[8..10].copy_from_slice(&(request.arguments.len() as u16).to_le_bytes());
    output[10..12].copy_from_slice(&(request.environment.len() as u16).to_le_bytes());
    for (index, value) in request.stdio_metadata.iter().enumerate() {
        output[16 + index * 8..24 + index * 8].copy_from_slice(&value.to_le_bytes());
    }
    let mut cursor = HEADER_BYTES;
    for text in core::iter::once(request.path)
        .chain(request.arguments.iter().copied())
        .chain(request.environment.iter().copied())
    {
        output[cursor..cursor + text.len()].copy_from_slice(text.as_bytes());
        cursor += text.len();
        output[cursor] = 0;
        cursor += 1;
    }
    Ok(length)
}

fn take_text<'a>(bytes: &mut &'a [u8]) -> Result<&'a str, Error> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::TooShort)?;
    let text = core::str::from_utf8(&bytes[..end]).map_err(|_| Error::InvalidUtf8)?;
    *bytes = &bytes[end + 1..];
    Ok(text)
}
fn vector<'a>(
    bytes: &mut &'a [u8],
    count: usize,
    is_environment: bool,
) -> Result<Strings<'a>, Error> {
    let start = *bytes;
    for _ in 0..count {
        let text = take_text(bytes)?;
        if is_environment {
            environment(text)?;
        }
    }
    Ok(Strings {
        bytes: &start[..start.len() - bytes.len()],
        count,
    })
}

pub fn decode(bytes: &[u8]) -> Result<Decoded<'_>, Error> {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_BYTES {
        return Err(Error::InvalidLength);
    }
    if u32::from_le_bytes(bytes[..4].try_into().unwrap()) != OPCODE {
        return Err(Error::UnknownOpcode);
    }
    if u32::from_le_bytes(bytes[4..8].try_into().unwrap()) != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if bytes[12..16] != [0; 4] {
        return Err(Error::InvalidField);
    }
    let arguments = u16::from_le_bytes(bytes[8..10].try_into().unwrap()) as usize;
    let variables = u16::from_le_bytes(bytes[10..12].try_into().unwrap()) as usize;
    if arguments == 0 || arguments + variables > MAX_ITEMS {
        return Err(Error::InvalidLength);
    }
    let mut metadata = [0; 3];
    for (index, value) in metadata.iter_mut().enumerate() {
        *value = u64::from_le_bytes(bytes[16 + index * 8..24 + index * 8].try_into().unwrap());
    }
    let mut remaining = &bytes[HEADER_BYTES..];
    let executable = take_text(&mut remaining)?;
    path(executable)?;
    let arguments = vector(&mut remaining, arguments, false)?;
    let environment = vector(&mut remaining, variables, true)?;
    if !remaining.is_empty() {
        return Err(Error::TrailingBytes);
    }
    Ok(Decoded {
        path: executable,
        arguments,
        environment,
        stdio_metadata: metadata,
    })
}
