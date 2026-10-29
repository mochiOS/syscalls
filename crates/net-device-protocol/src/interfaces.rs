//! Native network interface observations. No POSIX flags, FDs, pointers or
//! caller-supplied identities occur on this wire. One reply is one snapshot.
pub const SNAPSHOT: u16 = 1;
pub const MAX_REPLY: usize = 4096;
pub const HEADER_LEN: usize = 24;
pub const UP: u32 = 1;
pub const RUNNING: u32 = 2;
pub const LOOPBACK: u32 = 4;
pub const USABLE: u8 = 1;
const RECORD_LEN: usize = 16;
const ADDRESS_LEN: usize = 24;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Buffer,
}
pub fn request(op: u16) -> [u8; 8] {
    let [a, b] = op.to_le_bytes();
    [b'N', b'I', b'F', b'S', 1, 0, a, b]
}
pub fn operation(bytes: &[u8]) -> Result<u16, Error> {
    if bytes.len() != 8 || bytes[..6] != [b'N', b'I', b'F', b'S', 1, 0] {
        return Err(Error::Invalid);
    }
    Ok(u16::from_le_bytes([bytes[6], bytes[7]]))
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Address {
    V4 {
        bytes: [u8; 4],
        prefix: u8,
        flags: u8,
    },
    V6 {
        bytes: [u8; 16],
        prefix: u8,
        scope: u32,
        flags: u8,
    },
}
impl Address {
    fn encode(self, out: &mut [u8]) -> Result<(), Error> {
        out.fill(0);
        match self {
            Self::V4 {
                bytes,
                prefix,
                flags,
            } => {
                if prefix > 32 || flags & !USABLE != 0 {
                    return Err(Error::Invalid);
                }
                out[..2].copy_from_slice(&4u16.to_le_bytes());
                out[2] = prefix;
                out[3] = flags;
                out[8..12].copy_from_slice(&bytes);
            }
            Self::V6 {
                bytes,
                prefix,
                scope,
                flags,
            } => {
                if prefix > 128 || flags & !USABLE != 0 {
                    return Err(Error::Invalid);
                }
                out[..2].copy_from_slice(&6u16.to_le_bytes());
                out[2] = prefix;
                out[3] = flags;
                out[4..8].copy_from_slice(&scope.to_le_bytes());
                out[8..24].copy_from_slice(&bytes);
            }
        }
        Ok(())
    }
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let out = match u16_at(bytes, 0)? {
            4 if bytes[4..8] == [0; 4] && bytes[12..24] == [0; 12] => Self::V4 {
                bytes: bytes[8..12].try_into().unwrap(),
                prefix: bytes[2],
                flags: bytes[3],
            },
            6 => Self::V6 {
                bytes: bytes[8..24].try_into().unwrap(),
                prefix: bytes[2],
                scope: u32_at(bytes, 4)?,
                flags: bytes[3],
            },
            _ => return Err(Error::Invalid),
        };
        out.encode(&mut [0; ADDRESS_LEN])?;
        Ok(out)
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Interface<'a> {
    pub index: u32,
    pub flags: u32,
    pub mtu: u32,
    pub name: &'a str,
    pub addresses: &'a [Address],
}
fn valid(index: u32, flags: u32, mtu: u32, name: &str) -> Result<(), Error> {
    if index == 0
        || mtu == 0
        || flags & !(UP | RUNNING | LOOPBACK) != 0
        || name.is_empty()
        || name.len() > 63
        || name.bytes().any(|b| b == 0 || b == b'/')
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
pub fn failure(op: u16, status: i32, out: &mut [u8]) -> Result<usize, Error> {
    if status >= 0 || status == i32::MIN {
        return Err(Error::Invalid);
    }
    header(op, status, 0, HEADER_LEN, out)?;
    Ok(HEADER_LEN)
}
fn header(op: u16, status: i32, count: u32, length: usize, out: &mut [u8]) -> Result<(), Error> {
    let out = out.get_mut(..HEADER_LEN).ok_or(Error::Buffer)?;
    out.fill(0);
    out[..8].copy_from_slice(&request(op));
    out[3] = b'R';
    out[8..12].copy_from_slice(&status.to_le_bytes());
    out[12..16].copy_from_slice(&count.to_le_bytes());
    out[16..20].copy_from_slice(&(length as u32).to_le_bytes());
    Ok(())
}
pub fn encode<'a>(
    records: impl ExactSizeIterator<Item = Interface<'a>>,
    out: &mut [u8],
) -> Result<usize, Error> {
    let count = u32::try_from(records.len()).map_err(|_| Error::Invalid)?;
    let mut end = HEADER_LEN;
    for r in records {
        valid(r.index, r.flags, r.mtu, r.name)?;
        let addresses = u16::try_from(r.addresses.len()).map_err(|_| Error::Invalid)?;
        let length = RECORD_LEN
            .checked_add(r.name.len())
            .and_then(|n| n.checked_add(r.addresses.len().checked_mul(ADDRESS_LEN)?))
            .ok_or(Error::Buffer)?;
        let next = end.checked_add(length).ok_or(Error::Buffer)?;
        if next > MAX_REPLY {
            return Err(Error::Buffer);
        }
        let bytes = out.get_mut(end..next).ok_or(Error::Buffer)?;
        bytes.fill(0);
        bytes[..4].copy_from_slice(&r.index.to_le_bytes());
        bytes[4..8].copy_from_slice(&r.flags.to_le_bytes());
        bytes[8..12].copy_from_slice(&r.mtu.to_le_bytes());
        bytes[12..14].copy_from_slice(&(r.name.len() as u16).to_le_bytes());
        bytes[14..16].copy_from_slice(&addresses.to_le_bytes());
        bytes[RECORD_LEN..RECORD_LEN + r.name.len()].copy_from_slice(r.name.as_bytes());
        for (address, slot) in r
            .addresses
            .iter()
            .zip(bytes[RECORD_LEN + r.name.len()..].chunks_exact_mut(ADDRESS_LEN))
        {
            address.encode(slot)?;
        }
        end = next;
    }
    header(SNAPSHOT, 0, count, end, out)?;
    decode(&out[..end])?;
    Ok(end)
}
fn u16_at(bytes: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or(Error::Invalid)?
            .try_into()
            .unwrap(),
    ))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or(Error::Invalid)?
            .try_into()
            .unwrap(),
    ))
}

#[derive(Clone, Copy)]
pub struct Addresses<'a> {
    bytes: &'a [u8],
}
impl Iterator for Addresses<'_> {
    type Item = Address;
    fn next(&mut self) -> Option<Address> {
        let bytes = self.bytes.get(..ADDRESS_LEN)?;
        self.bytes = &self.bytes[ADDRESS_LEN..];
        Address::decode(bytes).ok()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.bytes.len() / ADDRESS_LEN;
        (n, Some(n))
    }
}
impl ExactSizeIterator for Addresses<'_> {}
#[derive(Clone, Copy)]
pub struct Record<'a> {
    pub index: u32,
    pub flags: u32,
    pub mtu: u32,
    pub name: &'a str,
    addresses: &'a [u8],
}
impl<'a> Record<'a> {
    pub fn addresses(self) -> Addresses<'a> {
        Addresses {
            bytes: self.addresses,
        }
    }
}
fn record(bytes: &[u8]) -> Result<(Record<'_>, usize), Error> {
    let index = u32_at(bytes, 0)?;
    let flags = u32_at(bytes, 4)?;
    let mtu = u32_at(bytes, 8)?;
    let name_len = usize::from(u16_at(bytes, 12)?);
    let count = usize::from(u16_at(bytes, 14)?);
    let start = RECORD_LEN.checked_add(name_len).ok_or(Error::Invalid)?;
    let end = start
        .checked_add(count.checked_mul(ADDRESS_LEN).ok_or(Error::Invalid)?)
        .ok_or(Error::Invalid)?;
    let name = core::str::from_utf8(bytes.get(RECORD_LEN..start).ok_or(Error::Invalid)?)
        .map_err(|_| Error::Invalid)?;
    valid(index, flags, mtu, name)?;
    let addresses = bytes.get(start..end).ok_or(Error::Invalid)?;
    for address in addresses.chunks_exact(ADDRESS_LEN) {
        if let Address::V6 { scope, .. } = Address::decode(address)? {
            if scope != 0 && scope != index {
                return Err(Error::Invalid);
            }
        }
    }
    Ok((
        Record {
            index,
            flags,
            mtu,
            name,
            addresses,
        },
        end,
    ))
}
#[derive(Clone, Copy)]
pub struct Records<'a> {
    bytes: &'a [u8],
}
impl<'a> Iterator for Records<'a> {
    type Item = Record<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let (row, n) = record(self.bytes).ok()?;
        self.bytes = &self.bytes[n..];
        Some(row)
    }
}
#[derive(Clone, Copy)]
pub struct Snapshot<'a> {
    pub status: i32,
    bytes: &'a [u8],
}
impl<'a> Snapshot<'a> {
    pub fn records(self) -> Records<'a> {
        Records { bytes: self.bytes }
    }
    pub fn index(self, name: &str) -> Option<u32> {
        self.records().find(|r| r.name == name).map(|r| r.index)
    }
}
pub fn decode(bytes: &[u8]) -> Result<Snapshot<'_>, Error> {
    let mut expected = request(SNAPSHOT);
    expected[3] = b'R';
    if bytes.len() < HEADER_LEN
        || bytes.len() > MAX_REPLY
        || bytes[..8] != expected
        || bytes[20..24] != [0; 4]
        || u32_at(bytes, 16)? as usize != bytes.len()
    {
        return Err(Error::Invalid);
    }
    let status = u32_at(bytes, 8)? as i32;
    let count = u32_at(bytes, 12)?;
    if status > 0
        || status == i32::MIN
        || (status != 0 && (count != 0 || bytes.len() != HEADER_LEN))
    {
        return Err(Error::Invalid);
    }
    let body = &bytes[HEADER_LEN..];
    let mut offset = 0;
    for _ in 0..count {
        let (r, n) = record(body.get(offset..).ok_or(Error::Invalid)?)?;
        for previous in (Records {
            bytes: &body[..offset],
        }) {
            if previous.index == r.index || previous.name == r.name {
                return Err(Error::Invalid);
            }
        }
        offset += n;
    }
    if offset != body.len() {
        return Err(Error::Invalid);
    }
    Ok(Snapshot {
        status,
        bytes: body,
    })
}
