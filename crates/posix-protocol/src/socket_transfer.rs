//! Ancillary staging. Authority is carried ONLY in IPC attachments: Begin
//! attaches socket WRITE, Append attaches transaction CONTROL then file leases.
//! Inline fields contain lengths, batch indices and FD dispatch metadata only.
use crate::{InheritedFdMetadata, ProtocolError, socket::MAX_TRANSFERRED_DESCRIPTORS};
pub const MAGIC: [u8; 4] = *b"SCMB";
pub const HEADER_LEN: usize = 16;
pub const BATCH_SIZE: usize = mnu_abi::IPC_MAX_OBJECT_HANDLES - 1;
pub const MAX_REQUEST_LEN: usize = HEADER_LEN + 8 * BATCH_SIZE;
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
        _ => Err(Error::UnknownOperation),
    }
}
