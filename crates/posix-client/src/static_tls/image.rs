//! Versioned initial TLS templates. Source addresses name the prepared child
//! image, never a buffer or pointer in the exec producer's address space.
use super::{Template, modules::Plan};

pub const MAGIC: u64 = u64::from_le_bytes(*b"MTLS0001");
pub const VERSION: u32 = 1;
pub const HEADER_BYTES: usize = 32;
pub const MODULE_BYTES: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error<E> {
    Invalid,
    TooLarge,
    Read(E),
}

pub fn encoded_length(count: usize) -> Option<usize> {
    if count == 0 || count > u32::MAX as usize {
        return None;
    }
    count.checked_mul(MODULE_BYTES)?.checked_add(HEADER_BYTES)
}

/// Allocation preflight; decode repeats every header/bounds check before use.
pub fn workspace<E>(
    base: usize,
    maximum: usize,
    mut read: impl FnMut(usize, &mut [u8]) -> Result<(), E>,
) -> Result<(usize, usize), Error<E>> {
    if base == 0
        || base % 8 != 0
        || maximum < HEADER_BYTES
        || base.checked_add(HEADER_BYTES).is_none()
    {
        return Err(Error::Invalid);
    }
    let mut b = [0; HEADER_BYTES];
    read(base, &mut b).map_err(Error::Read)?;
    let word = |at| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    let format = word(8);
    let count = (format >> 32) as usize;
    let length = usize::try_from(word(16)).map_err(|_| Error::TooLarge)?;
    if word(0) != MAGIC
        || format as u32 != VERSION
        || word(24) != 0
        || encoded_length(count) != Some(length)
    {
        return Err(Error::Invalid);
    }
    if length > maximum {
        return Err(Error::TooLarge);
    }
    base.checked_add(length).ok_or(Error::Invalid)?;
    Ok((count, length))
}

pub fn encode(
    templates: &[Option<Template>],
    output: &mut [u8],
) -> Result<usize, Error<core::convert::Infallible>> {
    let length = encoded_length(templates.len()).ok_or(Error::TooLarge)?;
    if output.len() < length {
        return Err(Error::TooLarge);
    }
    Plan::new(templates, 4096).ok_or(Error::Invalid)?;
    output[..length].fill(0);
    let put = |bytes: &mut [u8], offset: usize, value: u64| {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    };
    put(output, 0, MAGIC);
    put(
        output,
        8,
        u64::from(VERSION) | ((templates.len() as u64) << 32),
    );
    put(output, 16, length as u64);
    for (index, template) in templates.iter().enumerate() {
        if let Some(template) = template {
            let offset = HEADER_BYTES + index * MODULE_BYTES;
            for (word, value) in [
                template.source,
                template.file_size,
                template.memory_size,
                template.alignment,
                template.residue,
            ]
            .into_iter()
            .enumerate()
            {
                put(output, offset + word * 8, value as u64);
            }
        }
    }
    Ok(length)
}

/// Decode bounded metadata through the runtime's faultable copy operation.
/// The output is scratch until this returns success; no VM is created here.
pub fn decode<E>(
    base: usize,
    maximum: usize,
    templates: &mut [Option<Template>],
    mut read: impl FnMut(usize, &mut [u8]) -> Result<(), E>,
) -> Result<usize, Error<E>> {
    if base == 0 || base % 8 != 0 || maximum < HEADER_BYTES {
        return Err(Error::Invalid);
    }
    base.checked_add(HEADER_BYTES).ok_or(Error::Invalid)?;
    let mut header = [0; HEADER_BYTES];
    read(base, &mut header).map_err(Error::Read)?;
    let word =
        |bytes: &[u8], offset| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let format = word(&header, 8);
    let count = (format >> 32) as usize;
    let length = usize::try_from(word(&header, 16)).map_err(|_| Error::TooLarge)?;
    if word(&header, 0) != MAGIC
        || format as u32 != VERSION
        || word(&header, 24) != 0
        || encoded_length(count) != Some(length)
    {
        return Err(Error::Invalid);
    }
    if length > maximum || count > templates.len() {
        return Err(Error::TooLarge);
    }
    base.checked_add(length).ok_or(Error::Invalid)?;
    for (index, template) in templates[..count].iter_mut().enumerate() {
        let mut bytes = [0; MODULE_BYTES];
        read(base + HEADER_BYTES + index * MODULE_BYTES, &mut bytes).map_err(Error::Read)?;
        *template = if bytes.iter().all(|&byte| byte == 0) {
            None
        } else {
            let value = |offset| usize::try_from(word(&bytes, offset)).map_err(|_| Error::Invalid);
            Some(Template {
                source: value(0)?,
                file_size: value(8)?,
                memory_size: value(16)?,
                alignment: value(24)?,
                residue: value(32)?,
            })
        };
    }
    Plan::new(&templates[..count], 4096).ok_or(Error::Invalid)?;
    Ok(count)
}
