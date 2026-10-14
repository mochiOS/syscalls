//! Direct socket-worker record transport. Exactly two IPC attachments carry
//! socket and RAM-buffer authority; inline fields contain no PID, FD, handle
//! number or address-space pointer. Sender identity/delivery flags come from
//! the kernel. This envelope is separate from chunked native stream I/O.

use crate::{socket::Address, ProtocolError};

pub const MAX_RECORD_SIZE: usize = 64 * 1024;
pub const REQUEST_LEN: usize = 32;
pub const REPLY_HEADER_LEN: usize = 24;
pub const MAX_REPLY_LEN: usize = REPLY_HEADER_LEN + crate::socket::MAX_ADDRESS_LEN;
pub const REQUEST_MAGIC: [u8; 4] = *b"DGRM";
const REPLY_MAGIC: [u8; 4] = *b"DGRR";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Operation {
    Send = 1,
    Receive = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub operation: Operation,
    pub offset: u64,
    pub length: u32,
    pub peek: bool,
}

impl Request {
    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.length as usize > MAX_RECORD_SIZE
            || self.offset.checked_add(u64::from(self.length)).is_none()
            || self.operation == Operation::Send && self.peek
        {
            return Err(ProtocolError::InvalidLength);
        }
        Ok(())
    }

    pub fn encode(self) -> Result<[u8; REQUEST_LEN], ProtocolError> {
        self.validate()?;
        let mut output = [0; REQUEST_LEN];
        output[..4].copy_from_slice(&REQUEST_MAGIC);
        output[4..6].copy_from_slice(&VERSION.to_le_bytes());
        output[6..8].copy_from_slice(&(self.operation as u16).to_le_bytes());
        output[8..16].copy_from_slice(&self.offset.to_le_bytes());
        output[16..20].copy_from_slice(&self.length.to_le_bytes());
        output[20..24].copy_from_slice(&u32::from(self.peek).to_le_bytes());
        Ok(output)
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.len() != REQUEST_LEN || input[24..].iter().any(|byte| *byte != 0) {
            return Err(ProtocolError::InvalidLength);
        }
        validate_prefix(input, REQUEST_MAGIC)?;
        let operation = operation(input)?;
        let flags = u32::from_le_bytes(input[20..24].try_into().unwrap());
        if flags > 1 {
            return Err(ProtocolError::InvalidLength);
        }
        let request = Self {
            operation,
            offset: u64::from_le_bytes(input[8..16].try_into().unwrap()),
            length: u32::from_le_bytes(input[16..20].try_into().unwrap()),
            peek: flags != 0,
        };
        request.validate()?;
        Ok(request)
    }

    /// The receiver does not need re-transfer, CONTROL or descriptor cloning.
    /// The sender must separately possess TRANSFER to attach these references.
    pub const fn socket_rights(self) -> u64 {
        match self.operation {
            Operation::Send => mnu_abi::HANDLE_RIGHT_WRITE,
            Operation::Receive => mnu_abi::HANDLE_RIGHT_READ,
        }
    }

    /// MAP permits MemoryObjectLength to verify RAM type and live bounds;
    /// positioned RAM I/O then needs only the relevant data access right.
    pub const fn buffer_rights(self) -> u64 {
        mnu_abi::HANDLE_RIGHT_MAP
            | match self.operation {
                Operation::Send => mnu_abi::HANDLE_RIGHT_READ,
                Operation::Receive => mnu_abi::HANDLE_RIGHT_WRITE,
            }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply<'a> {
    pub copied: u32,
    pub length: u32,
    pub source: Option<Address<'a>>,
}

impl<'a> Reply<'a> {
    fn validate(self, request: Request) -> Result<(), ProtocolError> {
        request.validate()?;
        if self.length as usize > MAX_RECORD_SIZE
            || self.copied > request.length
            || self.copied > self.length
        {
            return Err(ProtocolError::InvalidLength);
        }
        match (request.operation, self.source) {
            (Operation::Send, None)
                if self.copied == request.length && self.length == request.length =>
            {
                Ok(())
            }
            (
                Operation::Receive,
                Some(Address::UnixUnnamed | Address::UnixPath(_) | Address::UnixAbstract(_)),
            ) if self.copied == request.length.min(self.length) => Ok(()),
            _ => Err(ProtocolError::InvalidLength),
        }
    }

    pub fn encode(self, request: Request, output: &mut [u8]) -> Result<usize, ProtocolError> {
        self.validate(request)?;
        let mut source = [0; crate::socket::MAX_ADDRESS_LEN];
        let source_length = match self.source {
            Some(address) => address.encode(&mut source)?,
            None => 0,
        };
        let total = REPLY_HEADER_LEN + source_length;
        if output.len() < total {
            return Err(ProtocolError::BufferTooSmall);
        }
        output[..total].fill(0);
        output[..4].copy_from_slice(&REPLY_MAGIC);
        output[4..6].copy_from_slice(&VERSION.to_le_bytes());
        output[6..8].copy_from_slice(&(request.operation as u16).to_le_bytes());
        output[8..12].copy_from_slice(&self.copied.to_le_bytes());
        output[12..16].copy_from_slice(&self.length.to_le_bytes());
        output[16..20].copy_from_slice(&(source_length as u32).to_le_bytes());
        output[REPLY_HEADER_LEN..total].copy_from_slice(&source[..source_length]);
        Ok(total)
    }

    pub fn decode(request: Request, input: &'a [u8]) -> Result<Self, ProtocolError> {
        if input.len() < REPLY_HEADER_LEN || input[20..24] != [0; 4] {
            return Err(ProtocolError::InvalidLength);
        }
        validate_prefix(input, REPLY_MAGIC)?;
        if operation(input)? != request.operation {
            return Err(ProtocolError::InvalidLength);
        }
        let source_length = u32::from_le_bytes(input[16..20].try_into().unwrap()) as usize;
        if input.len() - REPLY_HEADER_LEN != source_length {
            return Err(ProtocolError::InvalidLength);
        }
        let reply = Self {
            copied: u32::from_le_bytes(input[8..12].try_into().unwrap()),
            length: u32::from_le_bytes(input[12..16].try_into().unwrap()),
            source: if source_length == 0 {
                None
            } else {
                Some(Address::decode(&input[REPLY_HEADER_LEN..])?)
            },
        };
        reply.validate(request)?;
        Ok(reply)
    }
}

fn validate_prefix(input: &[u8], magic: [u8; 4]) -> Result<(), ProtocolError> {
    if input[..4] != magic {
        return Err(ProtocolError::InvalidMagic);
    }
    if input[4..6] != VERSION.to_le_bytes() {
        return Err(ProtocolError::UnsupportedVersion);
    }
    Ok(())
}

fn operation(input: &[u8]) -> Result<Operation, ProtocolError> {
    match u16::from_le_bytes(input[6..8].try_into().unwrap()) {
        1 => Ok(Operation::Send),
        2 => Ok(Operation::Receive),
        _ => Err(ProtocolError::InvalidLength),
    }
}
