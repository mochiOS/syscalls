//! Broker-to-presenter content shared by text and graphical consent. Decoding
//! proves structure, never sender authority; authenticate the IPC peer first.
use super::{Choice, Choices, Correlation, Error, Ticket};
use core::fmt;

const MAGIC: [u8; 8] = *b"MCNOFR01";
pub const VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 112;
pub const MAX_PACKAGE_BYTES: usize = 255;
pub const MAX_CAPABILITIES: usize = 128;
pub const MAX_CAPABILITY_BYTES: usize = 64;
pub const MAX_REQUIREMENTS_BYTES: usize = 1024;
pub const MAX_MESSAGE_BYTES: usize = HEADER_BYTES + MAX_PACKAGE_BYTES + MAX_REQUIREMENTS_BYTES;
pub const FETCH_OPCODE: u32 = u32::from_le_bytes(*b"MCNF");
pub const FETCH_BYTES: usize = 64;
const FETCH_MAGIC: [u8; 8] = *b"MCNFET01";

pub fn encode_fetch(correlation: Correlation) -> Result<[u8; FETCH_BYTES], Error> {
    if !correlation.ticket.is_valid() || correlation.display == 0 {
        return Err(Error::Invalid);
    }
    let mut bytes = [0; FETCH_BYTES];
    bytes[..8].copy_from_slice(&FETCH_MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
    bytes[16..24].copy_from_slice(&correlation.ticket.id.to_le_bytes());
    bytes[24..56].copy_from_slice(&correlation.ticket.challenge);
    bytes[56..64].copy_from_slice(&correlation.display.to_le_bytes());
    Ok(bytes)
}

pub fn decode_fetch(bytes: &[u8]) -> Result<Correlation, Error> {
    if bytes.len() != FETCH_BYTES || bytes[..8] != FETCH_MAGIC || bytes[10..16] != [0; 6] {
        return Err(Error::Invalid);
    }
    if u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    let correlation = Correlation {
        ticket: Ticket {
            id: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            challenge: bytes[24..56].try_into().unwrap(),
        },
        display: u64::from_le_bytes(bytes[56..64].try_into().unwrap()),
    };
    if !correlation.ticket.is_valid() || correlation.display == 0 {
        return Err(Error::Invalid);
    }
    Ok(correlation)
}

/// Display data, not an approval or a native execution permit. The source
/// digest includes the complete signed file, not just LOAD segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prompt<'a> {
    pub correlation: Correlation,
    pub deadline: u64,
    pub choices: Choices,
    pub source_digest: [u8; 32],
    pub package: &'a str,
    /// Canonical, sorted, unique ASCII names, each terminated with NUL.
    pub requirements: &'a [u8],
}

fn identifier(bytes: &[u8], limit: usize) -> bool {
    !bytes.is_empty()
        && bytes.len() <= limit
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(byte))
}

impl<'a> Prompt<'a> {
    fn validate(&self) -> Result<usize, Error> {
        if !self.correlation.ticket.is_valid()
            || self.correlation.display == 0
            || self.deadline == 0
            || !identifier(self.package.as_bytes(), MAX_PACKAGE_BYTES)
            || self.requirements.len() > MAX_REQUIREMENTS_BYTES
            || (!self.requirements.is_empty() && self.requirements.last() != Some(&0))
        {
            return Err(Error::Invalid);
        }
        let mut previous: Option<&[u8]> = None;
        let mut count = 0;
        for name in self.capabilities() {
            let name = name.as_bytes();
            if !identifier(name, MAX_CAPABILITY_BYTES)
                || previous.is_some_and(|previous| previous >= name)
            {
                return Err(Error::Invalid);
            }
            previous = Some(name);
            count += 1;
        }
        if count > MAX_CAPABILITIES {
            return Err(Error::Invalid);
        }
        Ok(count)
    }

    pub fn capabilities(&self) -> impl Iterator<Item = &'a str> {
        self.requirements
            .split_inclusive(|byte| *byte == 0)
            .map(|name| core::str::from_utf8(name.strip_suffix(&[0]).unwrap_or(name)).unwrap_or(""))
    }

    /// Both frontend types use these labels and only offered choices.
    pub fn label(&self, choice: Choice) -> Option<&'static str> {
        self.choices.contains(choice).then_some(match choice {
            Choice::Deny => "Don't Allow",
            Choice::AllowOnce => "Allow Once",
            Choice::AllowForProcess => "Allow for This Process",
            Choice::AllowPersistently => "Always Allow",
        })
    }

    /// This never reads stdin or authorizes execution. Positive decisions
    /// still need the controller's independently authenticated input evidence.
    pub fn write_text(&self, output: &mut impl fmt::Write) -> fmt::Result {
        self.validate().map_err(|_| fmt::Error)?;
        writeln!(output, "Allow {} to use these capabilities?", self.package)?;
        for capability in self.capabilities() {
            writeln!(output, "  {capability}")?;
        }
        write!(output, "Source SHA-256: ")?;
        for byte in self.source_digest {
            write!(output, "{byte:02x}")?;
        }
        writeln!(output)?;
        for choice in [
            Choice::Deny,
            Choice::AllowOnce,
            Choice::AllowForProcess,
            Choice::AllowPersistently,
        ] {
            if let Some(label) = self.label(choice) {
                writeln!(output, "  {label}")?;
            }
        }
        Ok(())
    }
}

pub fn encode(prompt: Prompt<'_>, output: &mut [u8]) -> Result<usize, Error> {
    let count = prompt.validate()?;
    let length = HEADER_BYTES + prompt.package.len() + prompt.requirements.len();
    let bytes = output.get_mut(..length).ok_or(Error::BufferTooSmall)?;
    bytes.fill(0);
    bytes[..8].copy_from_slice(&MAGIC);
    bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
    bytes[10] = prompt.choices.bits();
    bytes[16..24].copy_from_slice(&prompt.correlation.ticket.id.to_le_bytes());
    bytes[24..56].copy_from_slice(&prompt.correlation.ticket.challenge);
    bytes[56..64].copy_from_slice(&prompt.correlation.display.to_le_bytes());
    bytes[64..72].copy_from_slice(&prompt.deadline.to_le_bytes());
    bytes[72..104].copy_from_slice(&prompt.source_digest);
    bytes[104..106].copy_from_slice(&(prompt.package.len() as u16).to_le_bytes());
    bytes[106..108].copy_from_slice(&(prompt.requirements.len() as u16).to_le_bytes());
    bytes[108..110].copy_from_slice(&(count as u16).to_le_bytes());
    bytes[HEADER_BYTES..HEADER_BYTES + prompt.package.len()]
        .copy_from_slice(prompt.package.as_bytes());
    bytes[HEADER_BYTES + prompt.package.len()..].copy_from_slice(prompt.requirements);
    Ok(length)
}

pub fn decode(bytes: &[u8]) -> Result<Prompt<'_>, Error> {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_MESSAGE_BYTES || bytes[..8] != MAGIC {
        return Err(Error::Invalid);
    }
    if u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if bytes[11..16] != [0; 5] || bytes[110..112] != [0; 2] {
        return Err(Error::Invalid);
    }
    let package_len = u16::from_le_bytes(bytes[104..106].try_into().unwrap()) as usize;
    let requirements_len = u16::from_le_bytes(bytes[106..108].try_into().unwrap()) as usize;
    if bytes.len() != HEADER_BYTES + package_len + requirements_len {
        return Err(Error::Invalid);
    }
    let prompt = Prompt {
        correlation: Correlation {
            ticket: Ticket {
                id: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
                challenge: bytes[24..56].try_into().unwrap(),
            },
            display: u64::from_le_bytes(bytes[56..64].try_into().unwrap()),
        },
        deadline: u64::from_le_bytes(bytes[64..72].try_into().unwrap()),
        choices: Choices::new(bytes[10])?,
        source_digest: bytes[72..104].try_into().unwrap(),
        package: core::str::from_utf8(&bytes[HEADER_BYTES..HEADER_BYTES + package_len])
            .map_err(|_| Error::Invalid)?,
        requirements: &bytes[HEADER_BYTES + package_len..],
    };
    if prompt.validate()? != u16::from_le_bytes(bytes[108..110].try_into().unwrap()) as usize {
        return Err(Error::Invalid);
    }
    Ok(prompt)
}
