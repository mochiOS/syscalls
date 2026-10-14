//! Ancillary messages. Authority is carried ONLY in IPC attachments: send
//! staging attaches socket WRITE; consuming receive attaches socket READ.
//! File batches require transaction CONTROL and transfer explicit references.
//! Inline fields contain lengths, batch indices and FD dispatch metadata only.
use crate::{InheritedFdMetadata, ProtocolError, socket::MAX_TRANSFERRED_DESCRIPTORS};
pub const MAGIC: [u8; 4] = *b"SCMB";
pub const HEADER_LEN: usize = 16;
pub const BATCH_SIZE: usize = mnu_abi::IPC_MAX_OBJECT_HANDLES - 1;
pub const MAX_REQUEST_LEN: usize = HEADER_LEN + 8 * BATCH_SIZE;
pub const RECEIVE_REQUEST_LEN: usize = 32;
pub const RECEIVE_REPLY_HEADER_LEN: usize = 24;
pub const MAX_RECEIVE_REPLY_LEN: usize = RECEIVE_REPLY_HEADER_LEN + crate::socket::MAX_ADDRESS_LEN;
pub const MAX_DELIVERY_REPLY_LEN: usize = HEADER_LEN + 8 * mnu_abi::IPC_MAX_OBJECT_HANDLES;
pub const MAX_PAYLOAD_LEN: u32 = 128 * 1024 * 1024;
pub const RIGHTS: u64 =
    mnu_abi::HANDLE_RIGHT_CONTROL | mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_TRANSFER;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Protocol(ProtocolError),
    UnknownOperation,
}
impl From<ProtocolError> for Error {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    Begin {
        length: u32,
        descriptors: u16,
    },
    Append {
        offset: u16,
        count: u16,
        metadata: [Option<InheritedFdMetadata>; BATCH_SIZE],
    },
    /// Attaches transaction CONTROL and RAM READ|MAP. Length is bound at Begin.
    Commit {
        offset: u64,
    },
    /// Socket READ plus RAM WRITE|MAP; consuming receive, no client pointers.
    Receive {
        offset: u64,
        length: u32,
        maximum_rights: u16,
    },
    /// Receipt CONTROL; reply explicitly attaches up to four file references.
    Deliver {
        offset: u16,
        maximum: u16,
    },
}

fn valid_metadata(info: InheritedFdMetadata) -> bool {
    info.descriptor_flags == 0
        && info.open_flags & 3 != 3
        && crate::inherited_fd_kind_requires_handle(info.kind) == Some(true)
}
pub fn begin(length: u32, descriptors: u16) -> Result<[u8; HEADER_LEN], ProtocolError> {
    if length > MAX_PAYLOAD_LEN || descriptors as usize > MAX_TRANSFERRED_DESCRIPTORS {
        return Err(ProtocolError::InvalidLength);
    }
    let mut out = [0; HEADER_LEN];
    out[..4].copy_from_slice(&MAGIC);
    out[4..6].copy_from_slice(&1u16.to_le_bytes());
    out[6..8].copy_from_slice(&1u16.to_le_bytes());
    out[8..12].copy_from_slice(&length.to_le_bytes());
    out[12..14].copy_from_slice(&descriptors.to_le_bytes());
    Ok(out)
}
pub fn append(
    offset: u16,
    metadata: &[InheritedFdMetadata],
    out: &mut [u8],
) -> Result<usize, ProtocolError> {
    let count = metadata.len();
    if count == 0
        || count > BATCH_SIZE
        || offset as usize + count > MAX_TRANSFERRED_DESCRIPTORS
        || metadata.iter().any(|info| !valid_metadata(*info))
    {
        return Err(ProtocolError::InvalidLength);
    }
    let length = HEADER_LEN + 8 * count;
    if out.len() < length {
        return Err(ProtocolError::BufferTooSmall);
    }
    out[..length].fill(0);
    out[..4].copy_from_slice(&MAGIC);
    out[4..6].copy_from_slice(&1u16.to_le_bytes());
    out[6..8].copy_from_slice(&2u16.to_le_bytes());
    out[8..10].copy_from_slice(&offset.to_le_bytes());
    out[10..12].copy_from_slice(&(count as u16).to_le_bytes());
    for (info, bytes) in metadata
        .iter()
        .zip(out[HEADER_LEN..length].chunks_exact_mut(8))
    {
        bytes.copy_from_slice(
            &crate::encode_inherited_fd_metadata(*info)
                .unwrap()
                .to_le_bytes(),
        );
    }
    Ok(length)
}
pub fn decode(input: &[u8]) -> Result<Request, Error> {
    use ProtocolError::InvalidLength;
    if input.len() < HEADER_LEN {
        return Err(InvalidLength.into());
    }
    if input[..4] != MAGIC {
        return Err(ProtocolError::InvalidMagic.into());
    }
    if input[4..6] != 1u16.to_le_bytes() {
        return Err(ProtocolError::UnsupportedVersion.into());
    }
    match u16::from_le_bytes(input[6..8].try_into().unwrap()) {
        1 => {
            if input.len() != HEADER_LEN || input[14..16] != [0; 2] {
                return Err(InvalidLength.into());
            }
            let length = u32::from_le_bytes(input[8..12].try_into().unwrap());
            let descriptors = u16::from_le_bytes(input[12..14].try_into().unwrap());
            begin(length, descriptors)?;
            Ok(Request::Begin {
                length,
                descriptors,
            })
        }
        2 => {
            let offset = u16::from_le_bytes(input[8..10].try_into().unwrap());
            let count = u16::from_le_bytes(input[10..12].try_into().unwrap());
            if count == 0
                || count as usize > BATCH_SIZE
                || offset as usize + count as usize > MAX_TRANSFERRED_DESCRIPTORS
                || input.len() != HEADER_LEN + 8 * count as usize
                || input[12..16] != [0; 4]
            {
                return Err(InvalidLength.into());
            }
            let mut metadata = [None; BATCH_SIZE];
            for (target, bytes) in metadata.iter_mut().zip(input[HEADER_LEN..].chunks_exact(8)) {
                let info = crate::decode_inherited_fd_metadata(u64::from_le_bytes(
                    bytes.try_into().unwrap(),
                ))
                .ok_or(InvalidLength)?;
                if !valid_metadata(info) {
                    return Err(InvalidLength.into());
                }
                *target = Some(info);
            }
            Ok(Request::Append {
                offset,
                count,
                metadata,
            })
        }
        3 => {
            if input.len() != HEADER_LEN {
                return Err(InvalidLength.into());
            }
            Ok(Request::Commit {
                offset: u64::from_le_bytes(input[8..16].try_into().unwrap()),
            })
        }
        4 => {
            if input.len() != RECEIVE_REQUEST_LEN || input[22..].iter().any(|byte| *byte != 0) {
                return Err(InvalidLength.into());
            }
            let offset = u64::from_le_bytes(input[8..16].try_into().unwrap());
            let length = u32::from_le_bytes(input[16..20].try_into().unwrap());
            let maximum_rights = u16::from_le_bytes(input[20..22].try_into().unwrap());
            receive(offset, length, maximum_rights)?;
            Ok(Request::Receive {
                offset,
                length,
                maximum_rights,
            })
        }
        5 => {
            if input.len() != HEADER_LEN || input[12..].iter().any(|byte| *byte != 0) {
                return Err(InvalidLength.into());
            }
            let offset = u16::from_le_bytes(input[8..10].try_into().unwrap());
            let maximum = u16::from_le_bytes(input[10..12].try_into().unwrap());
            deliver(offset, maximum)?;
            Ok(Request::Deliver { offset, maximum })
        }
        _ => Err(Error::UnknownOperation),
    }
}

pub fn commit(offset: u64) -> [u8; HEADER_LEN] {
    let mut out = [0; HEADER_LEN];
    out[..4].copy_from_slice(&MAGIC);
    out[4..6].copy_from_slice(&1u16.to_le_bytes());
    out[6..8].copy_from_slice(&3u16.to_le_bytes());
    out[8..16].copy_from_slice(&offset.to_le_bytes());
    out
}

pub fn receive(
    offset: u64,
    length: u32,
    maximum_rights: u16,
) -> Result<[u8; RECEIVE_REQUEST_LEN], ProtocolError> {
    if length as usize > crate::socket_record::MAX_RECORD_SIZE
        || offset.checked_add(length as u64).is_none()
        || maximum_rights as usize > MAX_TRANSFERRED_DESCRIPTORS
    {
        return Err(ProtocolError::InvalidLength);
    }
    let mut out = [0; RECEIVE_REQUEST_LEN];
    out[..HEADER_LEN].copy_from_slice(&commit(offset));
    out[6..8].copy_from_slice(&4u16.to_le_bytes());
    out[16..20].copy_from_slice(&length.to_le_bytes());
    out[20..22].copy_from_slice(&maximum_rights.to_le_bytes());
    Ok(out)
}
pub fn deliver(offset: u16, maximum: u16) -> Result<[u8; HEADER_LEN], ProtocolError> {
    if offset as usize > MAX_TRANSFERRED_DESCRIPTORS
        || maximum == 0
        || maximum as usize > mnu_abi::IPC_MAX_OBJECT_HANDLES
    {
        return Err(ProtocolError::InvalidLength);
    }
    let mut out = [0; HEADER_LEN];
    out[..4].copy_from_slice(&MAGIC);
    out[4..6].copy_from_slice(&1u16.to_le_bytes());
    out[6..8].copy_from_slice(&5u16.to_le_bytes());
    out[8..10].copy_from_slice(&offset.to_le_bytes());
    out[10..12].copy_from_slice(&maximum.to_le_bytes());
    Ok(out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveReply<'a> {
    pub copied: u32,
    pub length: u32,
    pub total_rights: u16,
    pub available_rights: u16,
    pub source: crate::socket::Address<'a>,
}
impl<'a> ReceiveReply<'a> {
    fn validate(self, length: u32, maximum: u16) -> Result<(), ProtocolError> {
        receive(0, length, maximum)?;
        if self.length as usize > crate::socket_record::MAX_RECORD_SIZE
            || self.copied != length.min(self.length)
            || self.total_rights as usize > MAX_TRANSFERRED_DESCRIPTORS
            || maximum as usize > MAX_TRANSFERRED_DESCRIPTORS
            || self.available_rights != maximum.min(self.total_rights)
            || !matches!(
                self.source,
                crate::socket::Address::UnixUnnamed
                    | crate::socket::Address::UnixPath(_)
                    | crate::socket::Address::UnixAbstract(_)
            )
        {
            return Err(ProtocolError::InvalidLength);
        }
        Ok(())
    }
    pub fn encode(self, length: u32, maximum: u16, out: &mut [u8]) -> Result<usize, ProtocolError> {
        self.validate(length, maximum)?;
        let mut source = [0; crate::socket::MAX_ADDRESS_LEN];
        let count = self.source.encode(&mut source)?;
        let total = RECEIVE_REPLY_HEADER_LEN + count;
        if out.len() < total {
            return Err(ProtocolError::BufferTooSmall);
        }
        out[..total].fill(0);
        out[..4].copy_from_slice(b"SCMR");
        out[4..6].copy_from_slice(&1u16.to_le_bytes());
        out[6..8].copy_from_slice(&4u16.to_le_bytes());
        out[8..12].copy_from_slice(&self.copied.to_le_bytes());
        out[12..16].copy_from_slice(&self.length.to_le_bytes());
        out[16..18].copy_from_slice(&self.total_rights.to_le_bytes());
        out[18..20].copy_from_slice(&self.available_rights.to_le_bytes());
        out[20..22].copy_from_slice(&(count as u16).to_le_bytes());
        out[24..total].copy_from_slice(&source[..count]);
        Ok(total)
    }
    pub fn decode(length: u32, maximum: u16, input: &'a [u8]) -> Result<Self, ProtocolError> {
        if input.len() < RECEIVE_REPLY_HEADER_LEN || input[22..24] != [0; 2] {
            return Err(ProtocolError::InvalidLength);
        }
        reply_prefix(input, 4)?;
        let count = u16::from_le_bytes(input[20..22].try_into().unwrap()) as usize;
        if input.len() != RECEIVE_REPLY_HEADER_LEN + count {
            return Err(ProtocolError::InvalidLength);
        }
        let reply = Self {
            copied: u32::from_le_bytes(input[8..12].try_into().unwrap()),
            length: u32::from_le_bytes(input[12..16].try_into().unwrap()),
            total_rights: u16::from_le_bytes(input[16..18].try_into().unwrap()),
            available_rights: u16::from_le_bytes(input[18..20].try_into().unwrap()),
            source: crate::socket::Address::decode(&input[24..])?,
        };
        reply.validate(length, maximum)?;
        Ok(reply)
    }
}

fn reply_prefix(input: &[u8], operation: u16) -> Result<(), ProtocolError> {
    if input[..4] != *b"SCMR" {
        return Err(ProtocolError::InvalidMagic);
    }
    if input[4..6] != 1u16.to_le_bytes() {
        return Err(ProtocolError::UnsupportedVersion);
    }
    if input[6..8] != operation.to_le_bytes() {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(())
}
pub fn delivery_reply(
    offset: u16,
    metadata: &[InheritedFdMetadata],
    out: &mut [u8],
) -> Result<usize, ProtocolError> {
    if metadata.is_empty()
        || metadata.len() > mnu_abi::IPC_MAX_OBJECT_HANDLES
        || offset as usize + metadata.len() > MAX_TRANSFERRED_DESCRIPTORS
        || metadata.iter().any(|info| !valid_metadata(*info))
    {
        return Err(ProtocolError::InvalidLength);
    }
    let count = HEADER_LEN + 8 * metadata.len();
    if out.len() < count {
        return Err(ProtocolError::BufferTooSmall);
    }
    out[..count].fill(0);
    out[..4].copy_from_slice(b"SCMR");
    out[4..6].copy_from_slice(&1u16.to_le_bytes());
    out[6..8].copy_from_slice(&5u16.to_le_bytes());
    out[8..10].copy_from_slice(&offset.to_le_bytes());
    out[10..12].copy_from_slice(&(metadata.len() as u16).to_le_bytes());
    for (info, target) in metadata.iter().zip(out[16..count].chunks_exact_mut(8)) {
        target.copy_from_slice(
            &crate::encode_inherited_fd_metadata(*info)
                .unwrap()
                .to_le_bytes(),
        );
    }
    Ok(count)
}
pub fn decode_delivery(
    offset: u16,
    maximum: u16,
    input: &[u8],
) -> Result<
    (
        [Option<InheritedFdMetadata>; mnu_abi::IPC_MAX_OBJECT_HANDLES],
        usize,
    ),
    ProtocolError,
> {
    deliver(offset, maximum)?;
    if input.len() < HEADER_LEN || input[12..16] != [0; 4] {
        return Err(ProtocolError::InvalidLength);
    }
    reply_prefix(input, 5)?;
    let count = u16::from_le_bytes(input[10..12].try_into().unwrap()) as usize;
    if input[8..10] != offset.to_le_bytes()
        || count == 0
        || count > maximum as usize
        || offset as usize + count > MAX_TRANSFERRED_DESCRIPTORS
        || input.len() != HEADER_LEN + 8 * count
    {
        return Err(ProtocolError::InvalidLength);
    }
    let mut metadata = [None; mnu_abi::IPC_MAX_OBJECT_HANDLES];
    for (target, bytes) in metadata.iter_mut().zip(input[16..].chunks_exact(8)) {
        let info =
            crate::decode_inherited_fd_metadata(u64::from_le_bytes(bytes.try_into().unwrap()))
                .ok_or(ProtocolError::InvalidLength)?;
        if !valid_metadata(info) {
            return Err(ProtocolError::InvalidLength);
        }
        *target = Some(info);
    }
    Ok((metadata, count))
}
