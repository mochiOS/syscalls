//! A sendto lookup request contains only message length and serialized path.
//! It attaches source WRITE authority; the reply attaches a scoped send route.
use crate::{
    socket::{Address, MAX_ADDRESS_LEN},
    ProtocolError,
};
pub const MAGIC: [u8; 4] = *b"DGRT";
pub const HEADER_LEN: usize = 16;
pub const MAX_REQUEST_LEN: usize = HEADER_LEN + MAX_ADDRESS_LEN;
pub const RIGHTS: u64 =
    mnu_abi::HANDLE_RIGHT_WRITE | mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_TRANSFER;

pub fn encode(
    length: u32,
    address: Address<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    if length as usize > crate::socket_record::MAX_RECORD_SIZE
        || !matches!(address, Address::UnixPath(_))
    {
        return Err(ProtocolError::InvalidLength);
    }
    let mut name = [0; MAX_ADDRESS_LEN];
    let count = address.encode(&mut name)?;
    if output.len() < HEADER_LEN + count {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..HEADER_LEN].fill(0);
    output[..4].copy_from_slice(&MAGIC);
    output[4..6].copy_from_slice(&1u16.to_le_bytes());
    output[8..12].copy_from_slice(&length.to_le_bytes());
    output[12..16].copy_from_slice(&(count as u32).to_le_bytes());
    output[HEADER_LEN..HEADER_LEN + count].copy_from_slice(&name[..count]);
    Ok(HEADER_LEN + count)
}
pub fn decode(input: &[u8]) -> Result<(u32, Address<'_>), ProtocolError> {
    if input.len() < HEADER_LEN || input[6..8] != [0; 2] {
        return Err(ProtocolError::InvalidLength);
    }
    if input[..4] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    if input[4..6] != 1u16.to_le_bytes() {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let length = u32::from_le_bytes(input[8..12].try_into().unwrap());
    let count = u32::from_le_bytes(input[12..16].try_into().unwrap()) as usize;
    if length as usize > crate::socket_record::MAX_RECORD_SIZE || input.len() - HEADER_LEN != count
    {
        return Err(ProtocolError::InvalidLength);
    }
    let address = Address::decode(&input[HEADER_LEN..])?;
    if !matches!(address, Address::UnixPath(_)) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok((length, address))
}
