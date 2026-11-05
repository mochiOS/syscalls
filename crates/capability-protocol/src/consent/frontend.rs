//! A measured presenter waits for broker content and proposes decisions.
//! Requests contain no input witness, identity, grants, path or source digest.
use super::{Choice, Correlation, Error, Ticket};
pub const WAIT_OPCODE: u32 = u32::from_le_bytes(*b"MCNW");
pub const COMMAND_OPCODE: u32 = u32::from_le_bytes(*b"MCNC");
pub const TEXT_POLL_OPCODE: u32 = u32::from_le_bytes(*b"MCNP");
pub const TEXT_RELEASE_OPCODE: u32 = u32::from_le_bytes(*b"MCNX");
pub const WAIT_BYTES: usize = 16;
pub const COMMAND_BYTES: usize = 64;
const VERSION: u16 = 1;

/// Nonblocking text registration/offer retrieval. Attach exactly one PTY
/// master with CONTROL|TRANSFER. An idle success is an eight-byte zero status;
/// an offer uses the common prompt frame. Release withdraws that same object.
pub fn encode_text_poll(release: bool) -> [u8; WAIT_BYTES] {
    let mut bytes = [0; WAIT_BYTES];
    bytes[..4].copy_from_slice(
        &if release {
            TEXT_RELEASE_OPCODE
        } else {
            TEXT_POLL_OPCODE
        }
        .to_le_bytes(),
    );
    bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
    bytes
}
pub fn decode_text_poll(bytes: &[u8]) -> Result<bool, Error> {
    if bytes.len() != WAIT_BYTES || bytes[6..] != [0; 10] {
        return Err(Error::Invalid);
    }
    if bytes[4..6] != VERSION.to_le_bytes() {
        return Err(Error::UnsupportedVersion);
    }
    match u32::from_le_bytes(bytes[..4].try_into().unwrap()) {
        TEXT_POLL_OPCODE => Ok(false),
        TEXT_RELEASE_OPCODE => Ok(true),
        _ => Err(Error::UnknownKind),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Kind {
    Text = 1,
    Graphical = 2,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Presented,
    Decide(Choice),
    Dismissed,
}

pub fn encode_wait(kind: Kind) -> [u8; WAIT_BYTES] {
    let mut bytes = [0; WAIT_BYTES];
    bytes[..8].copy_from_slice(b"MCNWAIT1");
    bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&(kind as u16).to_le_bytes());
    bytes
}
pub fn decode_wait(bytes: &[u8]) -> Result<Kind, Error> {
    if bytes.len() != WAIT_BYTES || bytes[..8] != *b"MCNWAIT1" || bytes[12..] != [0; 4] {
        return Err(Error::Invalid);
    }
    if u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    match u16::from_le_bytes(bytes[10..12].try_into().unwrap()) {
        1 => Ok(Kind::Text),
        2 => Ok(Kind::Graphical),
        _ => Err(Error::UnknownKind),
    }
}
pub fn encode(correlation: Correlation, action: Action) -> Result<[u8; COMMAND_BYTES], Error> {
    if !correlation.ticket.is_valid() || correlation.display == 0 {
        return Err(Error::Invalid);
    }
    let mut bytes = [0; COMMAND_BYTES];
    bytes[..8].copy_from_slice(b"MCNCMD01");
    bytes[8..10].copy_from_slice(&VERSION.to_le_bytes());
    let (kind, choice) = match action {
        Action::Presented => (1u16, Choice::Deny),
        Action::Decide(choice) => (2, choice),
        Action::Dismissed => (3, Choice::Deny),
    };
    bytes[10..12].copy_from_slice(&kind.to_le_bytes());
    bytes[12] = choice as u8;
    bytes[16..24].copy_from_slice(&correlation.ticket.id.to_le_bytes());
    bytes[24..56].copy_from_slice(&correlation.ticket.challenge);
    bytes[56..64].copy_from_slice(&correlation.display.to_le_bytes());
    Ok(bytes)
}
pub fn decode(bytes: &[u8]) -> Result<(Correlation, Action), Error> {
    if bytes.len() != COMMAND_BYTES || bytes[..8] != *b"MCNCMD01" || bytes[13..16] != [0; 3] {
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
    let choice = match bytes[12] {
        0 => Choice::Deny,
        1 => Choice::AllowOnce,
        2 => Choice::AllowForProcess,
        3 => Choice::AllowPersistently,
        _ => return Err(Error::Invalid),
    };
    let action = match u16::from_le_bytes(bytes[10..12].try_into().unwrap()) {
        1 if choice == Choice::Deny => Action::Presented,
        2 => Action::Decide(choice),
        3 if choice == Choice::Deny => Action::Dismissed,
        _ => return Err(Error::Invalid),
    };
    Ok((correlation, action))
}
