//! Read-only group metadata, without credentials, hashes or application pointers.
use crate::{DecodeError, EncodeError, Opcode};
pub const MAX_NAME: usize = 32;
pub const MAX_MEMBERS: usize = 64;
pub const MAX_QUERY: usize = crate::public_account::MAX_QUERY;
pub const MAX_RECORD: usize = 8 + MAX_NAME + MAX_MEMBERS * (2 + MAX_NAME);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Query<'a> {
    Gid(u32),
    Name(&'a str),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub gid: u32,
    pub name: &'a str,
    members: [&'a str; MAX_MEMBERS],
    count: usize,
}
fn valid_name(bytes: &[u8]) -> Result<&str, DecodeError> {
    if bytes.is_empty()
        || bytes.len() > MAX_NAME
        || !bytes
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(*c, b'_' | b'-'))
    {
        return Err(DecodeError::InvalidLength);
    }
    core::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8)
}
impl<'a> Record<'a> {
    pub fn new(gid: u32, name: &'a str, members: &[&'a str]) -> Result<Self, EncodeError> {
        if members.len() > MAX_MEMBERS {
            return Err(EncodeError::ValueTooLong);
        }
        valid_name(name.as_bytes()).map_err(|_| EncodeError::InvalidLength)?;
        let mut record = Self {
            gid,
            name,
            members: [""; MAX_MEMBERS],
            count: members.len(),
        };
        for (index, member) in members.iter().enumerate() {
            valid_name(member.as_bytes()).map_err(|_| EncodeError::InvalidLength)?;
            if members[..index].contains(member) {
                return Err(EncodeError::InvalidLength);
            }
            record.members[index] = member;
        }
        Ok(record)
    }
    pub fn members(&self) -> &[&'a str] {
        &self.members[..self.count]
    }
}
pub fn encode_query(query: Query<'_>, output: &mut [u8]) -> Result<usize, EncodeError> {
    use crate::public_account as account;
    account::encode_query(
        match query {
            Query::Gid(id) => account::Query::Uid(id),
            Query::Name(name) => account::Query::Name(name),
        },
        output,
    )
}
pub fn decode_query(input: &[u8]) -> Result<Query<'_>, DecodeError> {
    use crate::public_account as account;
    Ok(match account::decode_query(input)? {
        account::Query::Uid(id) => Query::Gid(id),
        account::Query::Name(name) => Query::Name(name),
    })
}
pub fn encode_record(record: Record<'_>, output: &mut [u8]) -> Result<usize, EncodeError> {
    let record = Record::new(record.gid, record.name, record.members())?;
    let length = 8
        + record.name.len()
        + record
            .members()
            .iter()
            .map(|member| 2 + member.len())
            .sum::<usize>();
    crate::require_output(output, length)?;
    output[..4].copy_from_slice(&record.gid.to_le_bytes());
    output[4..6].copy_from_slice(&(record.name.len() as u16).to_le_bytes());
    output[6..8].copy_from_slice(&(record.count as u16).to_le_bytes());
    let mut offset = 8;
    output[offset..offset + record.name.len()].copy_from_slice(record.name.as_bytes());
    offset += record.name.len();
    for member in record.members() {
        output[offset..offset + 2].copy_from_slice(&(member.len() as u16).to_le_bytes());
        offset += 2;
        output[offset..offset + member.len()].copy_from_slice(member.as_bytes());
        offset += member.len();
    }
    Ok(offset)
}
pub fn decode_record(input: &[u8]) -> Result<Record<'_>, DecodeError> {
    if input.len() < 8 || input.len() > MAX_RECORD {
        return Err(DecodeError::InvalidLength);
    }
    let gid = u32::from_le_bytes(input[..4].try_into().unwrap());
    let name_len = u16::from_le_bytes(input[4..6].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(input[6..8].try_into().unwrap()) as usize;
    if count > MAX_MEMBERS {
        return Err(DecodeError::InvalidLength);
    }
    let name = valid_name(
        input
            .get(8..8 + name_len)
            .ok_or(DecodeError::InvalidLength)?,
    )?;
    let mut offset = 8 + name_len;
    let mut members = [""; MAX_MEMBERS];
    for index in 0..count {
        let bytes = input
            .get(offset..offset + 2)
            .ok_or(DecodeError::InvalidLength)?;
        let length = u16::from_le_bytes(bytes.try_into().unwrap()) as usize;
        offset += 2;
        let member = valid_name(
            input
                .get(offset..offset + length)
                .ok_or(DecodeError::InvalidLength)?,
        )?;
        offset += length;
        if members[..index].contains(&member) {
            return Err(DecodeError::InvalidLength);
        }
        members[index] = member;
    }
    if offset != input.len() {
        return Err(DecodeError::InvalidLength);
    }
    Ok(Record {
        gid,
        name,
        members,
        count,
    })
}
pub fn encode_request(id: u64, query: Query<'_>, output: &mut [u8]) -> Result<usize, EncodeError> {
    crate::require_output(output, crate::HEADER_LEN)?;
    let n = encode_query(query, &mut output[crate::HEADER_LEN..])?;
    crate::write_header(output, Opcode::PublicGroupLookup, id, n as u32);
    Ok(crate::HEADER_LEN + n)
}
pub fn decode_request(input: &[u8]) -> Result<(u64, Query<'_>), DecodeError> {
    let header = crate::expected_header(input, Opcode::PublicGroupLookup)?;
    Ok((
        header.request_id,
        decode_query(&input[crate::HEADER_LEN..])?,
    ))
}
pub fn encode_reply(id: u64, record: Record<'_>, output: &mut [u8]) -> Result<usize, EncodeError> {
    crate::require_output(output, crate::HEADER_LEN)?;
    let n = encode_record(record, &mut output[crate::HEADER_LEN..])?;
    crate::write_header(output, Opcode::PublicGroup, id, n as u32);
    Ok(crate::HEADER_LEN + n)
}
pub fn decode_response(id: u64, input: &[u8]) -> Result<Result<Record<'_>, i32>, DecodeError> {
    if crate::decode_opcode(input)? == Opcode::Status {
        let status = crate::Status::decode(input)?;
        if status.request_id != id || status.status >= 0 {
            return Err(DecodeError::InvalidLength);
        }
        return Ok(Err(status.status));
    }
    let header = crate::expected_header(input, Opcode::PublicGroup)?;
    if header.request_id != id {
        return Err(DecodeError::InvalidLength);
    }
    Ok(Ok(decode_record(&input[crate::HEADER_LEN..])?))
}
