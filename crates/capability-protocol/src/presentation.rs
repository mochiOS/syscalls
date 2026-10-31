//! Compositor-owned presentation receipts. Tokens identify an existing
//! registration; native IPC peers and attached Process references authorize it.
use crate::consent::{Correlation, Error, Ticket};
pub const SESSION_OPCODE: u32 = u32::from_le_bytes(*b"SCNS");
pub const CONTROL_OPCODE: u32 = u32::from_le_bytes(*b"PCNS");
const REPLY_OPCODE: u32 = u32::from_le_bytes(*b"PCRP");
const VERSION: u16 = 1;
pub const SESSION_BYTES: usize = 32;
pub const COMMAND_BYTES: usize = 88;
pub const RECEIPT_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub session: u64,
    pub generation: u64,
    pub active: bool,
}
impl Context {
    pub fn valid(self) -> bool {
        self.session != 0 && self.generation != 0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Kind {
    SecureOverlay = 1,
    Window = 2,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Register {
        context: Context,
        correlation: Correlation,
        kind: Kind,
    },
    Bind {
        correlation: Correlation,
        surface: u64,
    },
    Status {
        correlation: Correlation,
        registration: u64,
    },
    Cancel {
        correlation: Correlation,
        registration: u64,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image {
    pub process: u64,
    pub revision: u64,
    pub digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Stage {
    Pending = 0,
    Presented = 1,
    Revoked = 2,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub status: u32,
    pub stage: Stage,
    pub registration: u64,
    pub context: Context,
    pub focus_generation: u64,
    pub surface: u64,
    pub content_generation: u64,
    pub renderer: Image,
}
impl Receipt {
    pub fn failure(status: u32) -> Self {
        Self {
            status,
            stage: Stage::Pending,
            registration: 0,
            context: Context {
                session: 0,
                generation: 0,
                active: false,
            },
            focus_generation: 0,
            surface: 0,
            content_generation: 0,
            renderer: Image {
                process: 0,
                revision: 0,
                digest: [0; 32],
            },
        }
    }
}
fn get64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn put64(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn header(b: &mut [u8], opcode: u32, kind: u16) {
    b[..4].copy_from_slice(&opcode.to_le_bytes());
    b[4..6].copy_from_slice(&VERSION.to_le_bytes());
    b[6..8].copy_from_slice(&kind.to_le_bytes());
}
fn check(b: &[u8], length: usize, opcode: u32) -> Result<u16, Error> {
    if b.len() != length || b[..4] != opcode.to_le_bytes() {
        return Err(Error::Invalid);
    }
    if b[4..6] != VERSION.to_le_bytes() {
        return Err(Error::UnsupportedVersion);
    }
    Ok(u16::from_le_bytes(b[6..8].try_into().unwrap()))
}
fn valid(c: Correlation) -> Result<(), Error> {
    if !c.ticket.is_valid() || c.display == 0 {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}
fn put_correlation(b: &mut [u8], c: Correlation) {
    put64(b, 24, c.ticket.id);
    b[32..64].copy_from_slice(&c.ticket.challenge);
    put64(b, 64, c.display);
}
fn correlation(b: &[u8]) -> Result<Correlation, Error> {
    let c = Correlation {
        ticket: Ticket {
            id: get64(b, 24),
            challenge: b[32..64].try_into().unwrap(),
        },
        display: get64(b, 64),
    };
    valid(c)?;
    Ok(c)
}
pub fn encode_session(context: Context) -> Result<[u8; SESSION_BYTES], Error> {
    if !context.valid() {
        return Err(Error::Invalid);
    }
    let mut b = [0; SESSION_BYTES];
    header(&mut b, SESSION_OPCODE, 1);
    put64(&mut b, 8, context.session);
    put64(&mut b, 16, context.generation);
    b[24] = u8::from(context.active);
    Ok(b)
}
pub fn decode_session(b: &[u8]) -> Result<Context, Error> {
    if check(b, SESSION_BYTES, SESSION_OPCODE)? != 1 || b[24] > 1 || b[25..] != [0; 7] {
        return Err(Error::Invalid);
    }
    let c = Context {
        session: get64(b, 8),
        generation: get64(b, 16),
        active: b[24] != 0,
    };
    if !c.valid() {
        return Err(Error::Invalid);
    }
    Ok(c)
}
pub fn encode_command(command: Command) -> Result<[u8; COMMAND_BYTES], Error> {
    let mut b = [0; COMMAND_BYTES];
    let (kind, c, selector) = match command {
        Command::Register {
            context,
            correlation,
            kind,
        } => {
            if !context.valid() || !context.active {
                return Err(Error::Invalid);
            }
            put64(&mut b, 8, context.session);
            put64(&mut b, 16, context.generation);
            put64(&mut b, 80, kind as u64);
            (1, correlation, 0)
        }
        Command::Bind {
            correlation,
            surface,
        } => {
            if surface == 0 {
                return Err(Error::Invalid);
            }
            (2, correlation, surface)
        }
        Command::Status {
            correlation,
            registration,
        } => {
            if registration == 0 {
                return Err(Error::Invalid);
            }
            (3, correlation, registration)
        }
        Command::Cancel {
            correlation,
            registration,
        } => {
            if registration == 0 {
                return Err(Error::Invalid);
            }
            (4, correlation, registration)
        }
    };
    valid(c)?;
    header(&mut b, CONTROL_OPCODE, kind);
    put_correlation(&mut b, c);
    put64(&mut b, 72, selector);
    Ok(b)
}
pub fn decode_command(b: &[u8]) -> Result<Command, Error> {
    let kind = check(b, COMMAND_BYTES, CONTROL_OPCODE)?;
    let c = correlation(b)?;
    let selector = get64(b, 72);
    let flags = get64(b, 80);
    match kind {
        1 => {
            let context = Context {
                session: get64(b, 8),
                generation: get64(b, 16),
                active: true,
            };
            if !context.valid() || selector != 0 {
                return Err(Error::Invalid);
            }
            let kind = match flags {
                1 => Kind::SecureOverlay,
                2 => Kind::Window,
                _ => return Err(Error::Invalid),
            };
            Ok(Command::Register {
                context,
                correlation: c,
                kind,
            })
        }
        2..=4 => {
            if b[8..24] != [0; 16] || flags != 0 || selector == 0 {
                return Err(Error::Invalid);
            }
            Ok(match kind {
                2 => Command::Bind {
                    correlation: c,
                    surface: selector,
                },
                3 => Command::Status {
                    correlation: c,
                    registration: selector,
                },
                _ => Command::Cancel {
                    correlation: c,
                    registration: selector,
                },
            })
        }
        _ => Err(Error::UnknownKind),
    }
}
pub fn encode_receipt(receipt: Receipt) -> Result<[u8; RECEIPT_BYTES], Error> {
    let mut b = [0; RECEIPT_BYTES];
    header(&mut b, REPLY_OPCODE, 1);
    b[8..12].copy_from_slice(&receipt.status.to_le_bytes());
    if receipt.status != 0 {
        if receipt.status > 4095 || receipt != Receipt::failure(receipt.status) {
            return Err(Error::Invalid);
        }
        return Ok(b);
    }
    if receipt.registration == 0
        || !receipt.context.valid()
        || !receipt.context.active
        || receipt.renderer.process == 0
        || (receipt.stage == Stage::Presented
            && (receipt.focus_generation == 0
                || receipt.surface == 0
                || receipt.content_generation == 0))
    {
        return Err(Error::Invalid);
    }
    b[12..16].copy_from_slice(&(receipt.stage as u32).to_le_bytes());
    put64(&mut b, 16, receipt.registration);
    put64(&mut b, 24, receipt.context.session);
    put64(&mut b, 32, receipt.context.generation);
    put64(&mut b, 40, receipt.focus_generation);
    put64(&mut b, 48, receipt.surface);
    put64(&mut b, 56, receipt.content_generation);
    put64(&mut b, 64, receipt.renderer.process);
    put64(&mut b, 72, receipt.renderer.revision);
    b[80..112].copy_from_slice(&receipt.renderer.digest);
    Ok(b)
}
pub fn decode_receipt(b: &[u8]) -> Result<Receipt, Error> {
    if check(b, RECEIPT_BYTES, REPLY_OPCODE)? != 1 || b[112..] != [0; 16] {
        return Err(Error::Invalid);
    }
    let status = u32::from_le_bytes(b[8..12].try_into().unwrap());
    if status != 0 {
        let r = Receipt::failure(status);
        if encode_receipt(r)?.as_slice() != b {
            return Err(Error::Invalid);
        }
        return Ok(r);
    }
    let stage = match u32::from_le_bytes(b[12..16].try_into().unwrap()) {
        0 => Stage::Pending,
        1 => Stage::Presented,
        2 => Stage::Revoked,
        _ => return Err(Error::UnknownKind),
    };
    let r = Receipt {
        status,
        stage,
        registration: get64(b, 16),
        context: Context {
            session: get64(b, 24),
            generation: get64(b, 32),
            active: true,
        },
        focus_generation: get64(b, 40),
        surface: get64(b, 48),
        content_generation: get64(b, 56),
        renderer: Image {
            process: get64(b, 64),
            revision: get64(b, 72),
            digest: b[80..112].try_into().unwrap(),
        },
    };
    encode_receipt(r)?;
    Ok(r)
}
