//! Bounded public account data. Password hashes and authentication state have
//! no representation here. A lookup key is data, never sender authority.
use crate::{DecodeError, EncodeError, Opcode};

pub const MAX_NAME: usize = 32;
pub const MAX_DISPLAY: usize = 128;
pub const MAX_PATH: usize = 512;
pub const MAX_QUERY: usize = 8 + MAX_NAME;
pub const MAX_RECORD: usize = 16 + MAX_NAME + MAX_DISPLAY + 2 * MAX_PATH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Query<'a> {
    Uid(u32),
    Name(&'a str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub uid: u32,
    pub gid: u32,
    pub name: &'a str,
    pub display_name: &'a str,
    pub home: &'a str,
    pub shell: &'a str,
}

fn text(bytes: &[u8], limit: usize) -> Result<&str, DecodeError> {
    if bytes.len() > limit || bytes.contains(&0) {
        return Err(DecodeError::InvalidLength);
    }
    core::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8)
}
fn name(bytes: &[u8]) -> Result<&str, DecodeError> {
    let name = text(bytes, MAX_NAME)?;
    if name.is_empty()
        || !bytes
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(*c, b'_' | b'-'))
    {
        return Err(DecodeError::InvalidLength);
    }
    Ok(name)
}
pub fn encode_query(query: Query<'_>, output: &mut [u8]) -> Result<usize, EncodeError> {
    let (tag, value, tail) = match query {
        Query::Uid(uid) => (0u32, uid, &[][..]),
        Query::Name(value) => {
            name(value.as_bytes()).map_err(|_| EncodeError::InvalidLength)?;
            (1, value.len() as u32, value.as_bytes())
        }
    };
    crate::require_output(output, 8 + tail.len())?;
    output[..4].copy_from_slice(&tag.to_le_bytes());
    output[4..8].copy_from_slice(&value.to_le_bytes());
    output[8..8 + tail.len()].copy_from_slice(tail);
    Ok(8 + tail.len())
}
pub fn decode_query(input: &[u8]) -> Result<Query<'_>, DecodeError> {
    if input.len() < 8 || input.len() > MAX_QUERY {
        return Err(DecodeError::InvalidLength);
    }
    let tag = u32::from_le_bytes(input[..4].try_into().unwrap());
    let value = u32::from_le_bytes(input[4..8].try_into().unwrap());
    match tag {
        0 if input.len() == 8 => Ok(Query::Uid(value)),
        1 if (value as usize).checked_add(8) == Some(input.len()) => {
            Ok(Query::Name(name(&input[8..])?))
        }
        _ => Err(DecodeError::InvalidLength),
    }
}
pub fn encode_record(record: Record<'_>, output: &mut [u8]) -> Result<usize, EncodeError> {
    name(record.name.as_bytes()).map_err(|_| EncodeError::InvalidLength)?;
    let strings = [record.name, record.display_name, record.home, record.shell];
    for (value, limit) in strings
        .iter()
        .zip([MAX_NAME, MAX_DISPLAY, MAX_PATH, MAX_PATH])
    {
        text(value.as_bytes(), limit).map_err(|_| EncodeError::InvalidLength)?;
    }
    if !record.home.starts_with('/') || !record.shell.starts_with('/') {
        return Err(EncodeError::InvalidLength);
    }
    let length = 16 + strings.iter().map(|s| s.len()).sum::<usize>();
    crate::require_output(output, length)?;
    output[..4].copy_from_slice(&record.uid.to_le_bytes());
    output[4..8].copy_from_slice(&record.gid.to_le_bytes());
    let mut offset = 16;
    for (index, value) in strings.iter().enumerate() {
        output[8 + index * 2..10 + index * 2].copy_from_slice(&(value.len() as u16).to_le_bytes());
        output[offset..offset + value.len()].copy_from_slice(value.as_bytes());
        offset += value.len();
    }
    Ok(length)
}
pub fn decode_record(input: &[u8]) -> Result<Record<'_>, DecodeError> {
    if input.len() < 16 || input.len() > MAX_RECORD {
        return Err(DecodeError::InvalidLength);
    }
    let mut strings = [""; 4];
    let mut offset = 16usize;
    for (index, limit) in [MAX_NAME, MAX_DISPLAY, MAX_PATH, MAX_PATH]
        .into_iter()
        .enumerate()
    {
        let length =
            u16::from_le_bytes(input[8 + index * 2..10 + index * 2].try_into().unwrap()) as usize;
        let end = offset
            .checked_add(length)
            .ok_or(DecodeError::InvalidLength)?;
        strings[index] = text(
            input.get(offset..end).ok_or(DecodeError::InvalidLength)?,
            limit,
        )?;
        offset = end;
    }
    if offset != input.len() || !strings[2].starts_with('/') || !strings[3].starts_with('/') {
        return Err(DecodeError::InvalidLength);
    }
    name(strings[0].as_bytes())?;
    Ok(Record {
        uid: u32::from_le_bytes(input[..4].try_into().unwrap()),
        gid: u32::from_le_bytes(input[4..8].try_into().unwrap()),
        name: strings[0],
        display_name: strings[1],
        home: strings[2],
        shell: strings[3],
    })
}
pub fn encode_request(id: u64, query: Query<'_>, output: &mut [u8]) -> Result<usize, EncodeError> {
    crate::require_output(output, crate::HEADER_LEN)?;
    let length = encode_query(query, &mut output[crate::HEADER_LEN..])?;
    crate::write_header(output, Opcode::PublicLookup, id, length as u32);
    Ok(crate::HEADER_LEN + length)
}
pub fn decode_request(input: &[u8]) -> Result<(u64, Query<'_>), DecodeError> {
    let header = crate::expected_header(input, Opcode::PublicLookup)?;
    Ok((
        header.request_id,
        decode_query(&input[crate::HEADER_LEN..])?,
    ))
}
pub fn encode_reply(id: u64, record: Record<'_>, output: &mut [u8]) -> Result<usize, EncodeError> {
    crate::require_output(output, crate::HEADER_LEN)?;
    let length = encode_record(record, &mut output[crate::HEADER_LEN..])?;
    crate::write_header(output, Opcode::PublicAccount, id, length as u32);
    Ok(crate::HEADER_LEN + length)
}
pub fn decode_reply(input: &[u8]) -> Result<(u64, Record<'_>), DecodeError> {
    let header = crate::expected_header(input, Opcode::PublicAccount)?;
    Ok((
        header.request_id,
        decode_record(&input[crate::HEADER_LEN..])?,
    ))
}

/// Validate the request identity and distinguish a remote error from malformed data.
pub fn decode_response(id: u64, input: &[u8]) -> Result<Result<Record<'_>, i32>, DecodeError> {
    if crate::decode_opcode(input)? == Opcode::Status {
        let status = crate::Status::decode(input)?;
        if status.request_id != id || status.status >= 0 {
            return Err(DecodeError::InvalidLength);
        }
        return Ok(Err(status.status));
    }
    let (reply_id, record) = decode_reply(input)?;
    if reply_id != id {
        return Err(DecodeError::InvalidLength);
    }
    Ok(Ok(record))
}
pub const MAX_MESSAGE: usize = crate::HEADER_LEN + MAX_RECORD;
