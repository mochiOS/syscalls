//! Correlation and feedback shared by text and graphical consent presenters.
//! No field in this wire format authenticates its sender or proves user input.
//! The controller separately requires kernel-authenticated peers and evidence
//! from its registered input authority. Ordinary input bytes are not evidence.

const MAGIC: [u8; 8] = *b"MCNSNT01";
pub const FEEDBACK_OPCODE: u32 = u32::from_le_bytes(*b"MCNS");
pub const VERSION: u16 = 1;
pub const FEEDBACK_BYTES: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket {
    pub id: u64,
    /// Fresh service-generated cryptographic randomness, never a frontend ID.
    pub challenge: [u8; 32],
}

impl Ticket {
    pub fn is_valid(self) -> bool {
        self.id != 0 && self.challenge != [0; 32]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Choice {
    Deny = 0,
    AllowOnce = 1,
    AllowForProcess = 2,
    AllowPersistently = 3,
}

/// Denial is always available. Positive choices must be explicitly offered by
/// the service for this request; there is no implicit "allow all" permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Choices(u8);

impl Choices {
    pub const ONCE: u8 = 1;
    pub const PROCESS: u8 = 2;
    pub const PERSISTENT: u8 = 4;

    pub fn new(bits: u8) -> Result<Self, Error> {
        if bits & !(Self::ONCE | Self::PROCESS | Self::PERSISTENT) != 0 {
            return Err(Error::Invalid);
        }
        Ok(Self(bits))
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, choice: Choice) -> bool {
        let bit = match choice {
            Choice::Deny => return true,
            Choice::AllowOnce => Self::ONCE,
            Choice::AllowForProcess => Self::PROCESS,
            Choice::AllowPersistently => Self::PERSISTENT,
        };
        self.0 & bit != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Correlation {
    pub ticket: Ticket,
    pub display: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feedback {
    Presented,
    Decision {
        choice: Choice,
        /// Identifies separately authenticated input evidence. This number
        /// alone is never proof. Positive decisions require a nonzero serial.
        gesture: u64,
    },
    Dismissed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    UnsupportedVersion,
    UnknownKind,
    BufferTooSmall,
}

/// Explicit serialization, with exact lengths and reserved-field rejection.
/// Presentation text/requirements travel from the service separately. Feedback
/// carries no replacement target, resource, capability list or claimed PID.
pub fn encode(
    correlation: Correlation,
    feedback: Feedback,
    output: &mut [u8],
) -> Result<usize, Error> {
    let (kind, choice, gesture) = match feedback {
        Feedback::Presented => (1u16, Choice::Deny, 0),
        Feedback::Decision { choice, gesture } => {
            if (choice == Choice::Deny) != (gesture == 0) {
                return Err(Error::Invalid);
            }
            (2, choice, gesture)
        }
        Feedback::Dismissed => (3, Choice::Deny, 0),
    };
    if !correlation.ticket.is_valid() || correlation.display == 0 {
        return Err(Error::Invalid);
    }
    let output = output
        .get_mut(..FEEDBACK_BYTES)
        .ok_or(Error::BufferTooSmall)?;
    output.fill(0);
    output[..8].copy_from_slice(&MAGIC);
    output[8..10].copy_from_slice(&VERSION.to_le_bytes());
    output[10..12].copy_from_slice(&kind.to_le_bytes());
    output[16..24].copy_from_slice(&correlation.ticket.id.to_le_bytes());
    output[24..56].copy_from_slice(&correlation.ticket.challenge);
    output[56..64].copy_from_slice(&correlation.display.to_le_bytes());
    output[64] = choice as u8;
    output[72..80].copy_from_slice(&gesture.to_le_bytes());
    Ok(FEEDBACK_BYTES)
}

pub fn decode(input: &[u8]) -> Result<(Correlation, Feedback), Error> {
    if input.len() != FEEDBACK_BYTES || input[..8] != MAGIC {
        return Err(Error::Invalid);
    }
    if u16::from_le_bytes(input[8..10].try_into().unwrap()) != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if input[12..16] != [0; 4] || input[65..72] != [0; 7] {
        return Err(Error::Invalid);
    }
    let correlation = Correlation {
        ticket: Ticket {
            id: u64::from_le_bytes(input[16..24].try_into().unwrap()),
            challenge: input[24..56].try_into().unwrap(),
        },
        display: u64::from_le_bytes(input[56..64].try_into().unwrap()),
    };
    if !correlation.ticket.is_valid() || correlation.display == 0 {
        return Err(Error::Invalid);
    }
    let choice = match input[64] {
        0 => Choice::Deny,
        1 => Choice::AllowOnce,
        2 => Choice::AllowForProcess,
        3 => Choice::AllowPersistently,
        _ => return Err(Error::Invalid),
    };
    let gesture = u64::from_le_bytes(input[72..80].try_into().unwrap());
    let feedback = match u16::from_le_bytes(input[10..12].try_into().unwrap()) {
        1 if choice == Choice::Deny && gesture == 0 => Feedback::Presented,
        2 if (choice == Choice::Deny) == (gesture == 0) => Feedback::Decision { choice, gesture },
        3 if choice == Choice::Deny && gesture == 0 => Feedback::Dismissed,
        1..=3 => return Err(Error::Invalid),
        _ => return Err(Error::UnknownKind),
    };
    Ok((correlation, feedback))
}
