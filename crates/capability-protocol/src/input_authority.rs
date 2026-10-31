//! Private consent-input stream. Payloads never authenticate their sender.
//! The receiver must bind the native IPC peer and the registered input image.
use crate::consent::{Correlation, Error, Ticket};

pub const CONTROL_OPCODE: u32 = u32::from_le_bytes(*b"ICNS");
pub const EVENT_OPCODE: u32 = u32::from_le_bytes(*b"ICNE");
pub const INSTALL_OPCODE: u32 = u32::from_le_bytes(*b"ICNI");
const REPLY_OPCODE: u32 = u32::from_le_bytes(*b"ICNR");
const VERSION: u16 = 1;
pub const REQUEST_BYTES: usize = 64;
pub const REPLY_BYTES: usize = 40;
pub const EVENT_BYTES: usize = 80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Register,
    Arm {
        generation: u64,
        correlation: Correlation,
    },
    Cancel {
        generation: u64,
        correlation: Correlation,
    },
    Status {
        generation: u64,
        correlation: Correlation,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    /// Positive POSIX wire error. Failure carries no usable snapshot.
    pub status: u32,
    pub generation: u64,
    pub serial: u64,
    pub all_released: bool,
}
impl Reply {
    pub const fn failure(status: u32) -> Self {
        Self {
            status,
            generation: 0,
            serial: 0,
            all_released: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Transition {
    AllReleased = 1,
    PhysicalPress = 2,
    Repeat = 3,
    Synthetic = 4,
    Release = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub serial: u64,
    pub transition: Transition,
    /// Set-1 keyboard code, extended bit 7; pointer buttons use 256..=258.
    /// This describes the authority's observation, never a claimed choice.
    pub control: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub generation: u64,
    pub correlation: Correlation,
    pub observation: Observation,
}

fn header(output: &mut [u8], opcode: u32, kind: u16) {
    output[..4].copy_from_slice(&opcode.to_le_bytes());
    output[4..6].copy_from_slice(&VERSION.to_le_bytes());
    output[6..8].copy_from_slice(&kind.to_le_bytes());
}
fn check(input: &[u8], length: usize, opcode: u32) -> Result<u16, Error> {
    if input.len() != length || input[..4] != opcode.to_le_bytes() {
        return Err(Error::Invalid);
    }
    if input[4..6] != VERSION.to_le_bytes() {
        return Err(Error::UnsupportedVersion);
    }
    Ok(u16::from_le_bytes(input[6..8].try_into().unwrap()))
}
fn valid(generation: u64, correlation: Correlation) -> Result<(), Error> {
    if generation == 0 || !correlation.ticket.is_valid() || correlation.display == 0 {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn write_binding(output: &mut [u8], generation: u64, correlation: Correlation) {
    output[8..16].copy_from_slice(&generation.to_le_bytes());
    output[16..24].copy_from_slice(&correlation.ticket.id.to_le_bytes());
    output[24..56].copy_from_slice(&correlation.ticket.challenge);
    output[56..64].copy_from_slice(&correlation.display.to_le_bytes());
}
fn binding(input: &[u8]) -> Result<(u64, Correlation), Error> {
    let generation = u64::from_le_bytes(input[8..16].try_into().unwrap());
    let correlation = Correlation {
        ticket: Ticket {
            id: u64::from_le_bytes(input[16..24].try_into().unwrap()),
            challenge: input[24..56].try_into().unwrap(),
        },
        display: u64::from_le_bytes(input[56..64].try_into().unwrap()),
    };
    valid(generation, correlation)?;
    Ok((generation, correlation))
}

pub fn encode_command(command: Command) -> Result<[u8; REQUEST_BYTES], Error> {
    let mut output = [0; REQUEST_BYTES];
    let (kind, fields) = match command {
        Command::Register => (1, None),
        Command::Arm {
            generation,
            correlation,
        } => (2, Some((generation, correlation))),
        Command::Cancel {
            generation,
            correlation,
        } => (3, Some((generation, correlation))),
        Command::Status {
            generation,
            correlation,
        } => (4, Some((generation, correlation))),
    };
    header(&mut output, CONTROL_OPCODE, kind);
    if let Some((generation, correlation)) = fields {
        valid(generation, correlation)?;
        write_binding(&mut output, generation, correlation);
    }
    Ok(output)
}
pub fn decode_command(input: &[u8]) -> Result<Command, Error> {
    let kind = check(input, REQUEST_BYTES, CONTROL_OPCODE)?;
    if kind == 1 {
        return if input[8..].iter().all(|byte| *byte == 0) {
            Ok(Command::Register)
        } else {
            Err(Error::Invalid)
        };
    }
    let (generation, correlation) = binding(input)?;
    match kind {
        2 => Ok(Command::Arm {
            generation,
            correlation,
        }),
        3 => Ok(Command::Cancel {
            generation,
            correlation,
        }),
        4 => Ok(Command::Status {
            generation,
            correlation,
        }),
        _ => Err(Error::UnknownKind),
    }
}
pub fn encode_reply(reply: Reply) -> Result<[u8; REPLY_BYTES], Error> {
    if (reply.status == 0 && reply.generation == 0)
        || reply.status > 4095
        || (reply.status != 0 && (reply.generation != 0 || reply.serial != 0 || reply.all_released))
    {
        return Err(Error::Invalid);
    }
    let mut output = [0; REPLY_BYTES];
    header(&mut output, REPLY_OPCODE, 1);
    output[8..12].copy_from_slice(&reply.status.to_le_bytes());
    output[12..16].copy_from_slice(&u32::from(reply.all_released).to_le_bytes());
    output[16..24].copy_from_slice(&reply.generation.to_le_bytes());
    output[24..32].copy_from_slice(&reply.serial.to_le_bytes());
    Ok(output)
}
pub fn decode_reply(input: &[u8]) -> Result<Reply, Error> {
    if check(input, REPLY_BYTES, REPLY_OPCODE)? != 1 || input[32..40] != [0; 8] {
        return Err(Error::Invalid);
    }
    let flags = u32::from_le_bytes(input[12..16].try_into().unwrap());
    if flags > 1 {
        return Err(Error::Invalid);
    }
    let result = Reply {
        status: u32::from_le_bytes(input[8..12].try_into().unwrap()),
        generation: u64::from_le_bytes(input[16..24].try_into().unwrap()),
        serial: u64::from_le_bytes(input[24..32].try_into().unwrap()),
        all_released: flags != 0,
    };
    encode_reply(result)?;
    Ok(result)
}
pub fn encode_event(event: Event) -> Result<[u8; EVENT_BYTES], Error> {
    valid(event.generation, event.correlation)?;
    if event.observation.serial == 0 || !(1..=258).contains(&event.observation.control) {
        return Err(Error::Invalid);
    }
    let mut output = [0; EVENT_BYTES];
    header(
        &mut output,
        EVENT_OPCODE,
        event.observation.transition as u16,
    );
    write_binding(&mut output, event.generation, event.correlation);
    output[64..72].copy_from_slice(&event.observation.serial.to_le_bytes());
    output[72..74].copy_from_slice(&event.observation.control.to_le_bytes());
    Ok(output)
}
pub fn decode_event(input: &[u8]) -> Result<Event, Error> {
    let transition = match check(input, EVENT_BYTES, EVENT_OPCODE)? {
        1 => Transition::AllReleased,
        2 => Transition::PhysicalPress,
        3 => Transition::Repeat,
        4 => Transition::Synthetic,
        5 => Transition::Release,
        _ => return Err(Error::UnknownKind),
    };
    if input[74..] != [0; 6] {
        return Err(Error::Invalid);
    }
    let (generation, correlation) = binding(input)?;
    let event = Event {
        generation,
        correlation,
        observation: Observation {
            serial: u64::from_le_bytes(input[64..72].try_into().unwrap()),
            transition,
            control: u16::from_le_bytes(input[72..74].try_into().unwrap()),
        },
    };
    encode_event(event)?;
    Ok(event)
}
