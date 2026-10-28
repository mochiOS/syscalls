//! DNS authority and immutable query snapshots. Object identities are native
//! Handle attachments, never sender-supplied PID/FD/provider identifiers.
pub const ACQUIRE: u16 = 1;
pub const OPEN: u16 = 2;
pub const VALIDATE: u16 = 3;
pub const DERIVE: u16 = 4;
pub const A_SCOPE: u32 = 1;
pub const AAAA_SCOPE: u32 = 2;
pub const PTR_SCOPE: u32 = 4;
pub const ALL_SCOPES: u32 = A_SCOPE | AAAA_SCOPE | PTR_SCOPE;
pub const MAX_TIMEOUT: u32 = 30_000;
pub const MAX_RESULT_LEN: usize = 2 * 1024 * 1024;
pub const MAX_RECORDS: usize = 65535 / 11;
pub const MAX_ALIASES: usize = 16;
pub const REPLY_LEN: usize = 16;
pub const LIMITS_LEN: usize = 16;
pub const OBSERVATION_LEN: usize = 24;
pub const RESULT_HEADER_LEN: usize = 40;
pub const QUERY_LIMITS: u64 = u64::from_le_bytes(*b"NDNSLIM1");
pub const STATUS: u64 = u64::from_le_bytes(*b"NDNSSTA1");
pub const CANCEL: u64 = u64::from_le_bytes(*b"NDNSCAN1");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Buffer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Kind {
    A = 1,
    Ptr = 12,
    Aaaa = 28,
}
impl Kind {
    pub fn decode(value: u16) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::A),
            12 => Ok(Self::Ptr),
            28 => Ok(Self::Aaaa),
            _ => Err(Error::Invalid),
        }
    }
    pub const fn scope(self) -> u32 {
        match self {
            Self::A => A_SCOPE,
            Self::Aaaa => AAAA_SCOPE,
            Self::Ptr => PTR_SCOPE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Name<'a>(&'a [u8]);
impl<'a> Name<'a> {
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > 255 {
            return Err(Error::Invalid);
        }
        let mut offset = 0;
        loop {
            let length = usize::from(*bytes.get(offset).ok_or(Error::Invalid)?);
            if length > 63 {
                return Err(Error::Invalid);
            }
            offset += 1;
            if length == 0 {
                return if offset == bytes.len() {
                    Ok(Self(bytes))
                } else {
                    Err(Error::Invalid)
                };
            }
            offset = offset.checked_add(length).ok_or(Error::Invalid)?;
        }
    }
    pub fn bytes(self) -> &'a [u8] {
        self.0
    }
    pub fn matches(self, other: Self) -> bool {
        self.0.eq_ignore_ascii_case(other.0)
    }
}

pub fn header(op: u16) -> [u8; 8] {
    let [a, b] = op.to_le_bytes();
    [b'N', b'D', b'N', b'S', 1, 0, a, b]
}
pub fn operation(bytes: &[u8]) -> Result<u16, Error> {
    if bytes.len() < 8 || bytes[..6] != [b'N', b'D', b'N', b'S', 1, 0] {
        return Err(Error::Invalid);
    }
    Ok(u16::from_le_bytes([bytes[6], bytes[7]]))
}
pub fn scoped(op: u16, limits: Limits) -> Result<[u8; 16], Error> {
    limits.valid()?;
    if !matches!(op, ACQUIRE | DERIVE) {
        return Err(Error::Invalid);
    }
    let mut out = [0; 16];
    out[..8].copy_from_slice(&header(op));
    out[8..12].copy_from_slice(&limits.scopes.to_le_bytes());
    out[12..].copy_from_slice(&limits.maximum_timeout.to_le_bytes());
    Ok(out)
}
pub fn decode_scoped(bytes: &[u8]) -> Result<Limits, Error> {
    if !matches!(operation(bytes)?, ACQUIRE | DERIVE) || bytes.len() != 16 {
        return Err(Error::Invalid);
    }
    let limits = Limits {
        scopes: u32_at(bytes, 8)?,
        maximum_timeout: u32_at(bytes, 12)?,
    };
    limits.valid()?;
    Ok(limits)
}
pub fn reply(op: u16, status: i32, out: &mut [u8]) -> Result<usize, Error> {
    if status > 0 || status == i32::MIN {
        return Err(Error::Invalid);
    }
    let out = out.get_mut(..REPLY_LEN).ok_or(Error::Buffer)?;
    out.fill(0);
    out[..8].copy_from_slice(&header(op));
    out[3] = b'R';
    out[8..12].copy_from_slice(&status.to_le_bytes());
    Ok(REPLY_LEN)
}
pub fn reply_status(op: u16, bytes: &[u8]) -> Result<i32, Error> {
    let mut expected = header(op);
    expected[3] = b'R';
    if bytes.len() != REPLY_LEN || bytes[..8] != expected || bytes[12..] != [0; 4] {
        return Err(Error::Invalid);
    }
    let value = u32_at(bytes, 8)? as i32;
    if value > 0 || value == i32::MIN {
        return Err(Error::Invalid);
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub scopes: u32,
    pub maximum_timeout: u32,
}
impl Limits {
    fn valid(self) -> Result<(), Error> {
        if self.scopes == 0
            || self.scopes & !ALL_SCOPES != 0
            || self.maximum_timeout == 0
            || self.maximum_timeout > MAX_TIMEOUT
        {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }
    pub fn contains(self, other: Self) -> bool {
        self.valid().is_ok()
            && other.valid().is_ok()
            && other.scopes & self.scopes == other.scopes
            && other.maximum_timeout <= self.maximum_timeout
    }
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        self.valid()?;
        let out = out.get_mut(..LIMITS_LEN).ok_or(Error::Buffer)?;
        out.fill(0);
        out[..4].copy_from_slice(&[1, 0, 1, 0]);
        out[4..8].copy_from_slice(&self.scopes.to_le_bytes());
        out[8..12].copy_from_slice(&(MAX_RESULT_LEN as u32).to_le_bytes());
        out[12..].copy_from_slice(&self.maximum_timeout.to_le_bytes());
        Ok(LIMITS_LEN)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != LIMITS_LEN
            || bytes[..4] != [1, 0, 1, 0]
            || u32_at(bytes, 8)? != MAX_RESULT_LEN as u32
        {
            return Err(Error::Invalid);
        }
        let value = Self {
            scopes: u32_at(bytes, 4)?,
            maximum_timeout: u32_at(bytes, 12)?,
        };
        value.valid()?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request<'a> {
    pub kind: Kind,
    pub timeout: u32,
    pub name: Name<'a>,
}
impl<'a> Request<'a> {
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        if self.timeout == 0 || self.timeout > MAX_TIMEOUT {
            return Err(Error::Invalid);
        }
        let n = 24 + self.name.0.len();
        let out = out.get_mut(..n).ok_or(Error::Buffer)?;
        out.fill(0);
        out[..8].copy_from_slice(&header(OPEN));
        out[8..10].copy_from_slice(&(self.kind as u16).to_le_bytes());
        out[12..16].copy_from_slice(&self.timeout.to_le_bytes());
        out[16..18].copy_from_slice(&(self.name.0.len() as u16).to_le_bytes());
        out[24..].copy_from_slice(self.name.0);
        Ok(n)
    }
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if operation(bytes)? != OPEN
            || bytes.len() < 24
            || bytes[10..12] != [0; 2]
            || bytes[18..24] != [0; 6]
            || usize::from(u16_at(bytes, 16)?) != bytes.len() - 24
        {
            return Err(Error::Invalid);
        }
        let value = Self {
            kind: Kind::decode(u16_at(bytes, 8)?)?,
            timeout: u32_at(bytes, 12)?,
            name: Name::decode(&bytes[24..])?,
        };
        if value.timeout == 0 || value.timeout > MAX_TIMEOUT {
            return Err(Error::Invalid);
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub ready: bool,
    pub kind: Kind,
    pub status: i32,
    pub length: u64,
}
impl Observation {
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        if self.status > 0
            || self.status == i32::MIN
            || self.length > MAX_RESULT_LEN as u64
            || (!self.ready && (self.status != 0 || self.length != 0))
            || (self.ready && self.length < (RESULT_HEADER_LEN + 1) as u64)
        {
            return Err(Error::Invalid);
        }
        let out = out.get_mut(..OBSERVATION_LEN).ok_or(Error::Buffer)?;
        out.fill(0);
        out[..2].copy_from_slice(&1u16.to_le_bytes());
        out[2..4].copy_from_slice(&u16::from(self.ready).to_le_bytes());
        out[4..6].copy_from_slice(&(self.kind as u16).to_le_bytes());
        out[8..12].copy_from_slice(&self.status.to_le_bytes());
        out[16..24].copy_from_slice(&self.length.to_le_bytes());
        Ok(OBSERVATION_LEN)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != OBSERVATION_LEN
            || u16_at(bytes, 0)? != 1
            || u16_at(bytes, 2)? > 1
            || bytes[6..8] != [0; 2]
            || bytes[12..16] != [0; 4]
        {
            return Err(Error::Invalid);
        }
        let value = Self {
            ready: u16_at(bytes, 2)? == 1,
            kind: Kind::decode(u16_at(bytes, 4)?)?,
            status: u32_at(bytes, 8)? as i32,
            length: u64::from_le_bytes(bytes[16..24].try_into().map_err(|_| Error::Invalid)?),
        };
        value.encode(&mut [0; OBSERVATION_LEN])?;
        Ok(value)
    }
}

fn value_valid(kind: Kind, value: &[u8]) -> Result<(), Error> {
    match kind {
        Kind::A if value.len() == 4 => Ok(()),
        Kind::Aaaa if value.len() == 16 => Ok(()),
        Kind::Ptr => Name::decode(value).map(|_| ()),
        _ => Err(Error::Invalid),
    }
}

pub fn encode_result<'a>(
    kind: Kind,
    status: i32,
    question: Name<'a>,
    canonical: Option<Name<'a>>,
    cached: bool,
    aliases: impl ExactSizeIterator<Item = &'a [u8]>,
    values: impl ExactSizeIterator<Item = &'a [u8]>,
    out: &mut [u8],
) -> Result<usize, Error> {
    let alias_count = aliases.len();
    let count = values.len();
    if status > 0
        || status == i32::MIN
        || alias_count > MAX_ALIASES
        || count > MAX_RECORDS
        || (status != 0 && (canonical.is_some() || cached || alias_count != 0 || count != 0))
        || (status == 0 && canonical.is_none())
    {
        return Err(Error::Invalid);
    }
    let fixed = RESULT_HEADER_LEN + question.0.len() + canonical.map_or(0, |name| name.0.len());
    let output = out.get_mut(..fixed).ok_or(Error::Buffer)?;
    output.fill(0);
    output[..8].copy_from_slice(b"NDNSRSLT");
    output[8..10].copy_from_slice(&1u16.to_le_bytes());
    output[10..12].copy_from_slice(&(kind as u16).to_le_bytes());
    output[12..16].copy_from_slice(&status.to_le_bytes());
    output[16..20].copy_from_slice(&u32::from(cached).to_le_bytes());
    output[20..24].copy_from_slice(&(count as u32).to_le_bytes());
    output[24..26].copy_from_slice(&(question.0.len() as u16).to_le_bytes());
    output[26..28].copy_from_slice(&(canonical.map_or(0, |n| n.0.len()) as u16).to_le_bytes());
    output[28..30].copy_from_slice(&(alias_count as u16).to_le_bytes());
    output[RESULT_HEADER_LEN..RESULT_HEADER_LEN + question.0.len()].copy_from_slice(question.0);
    if let Some(name) = canonical {
        output[RESULT_HEADER_LEN + question.0.len()..].copy_from_slice(name.0);
    }
    let mut end = fixed;
    for alias in aliases {
        Name::decode(alias)?;
        end = append(out, end, alias)?;
    }
    for value in values {
        value_valid(kind, value)?;
        end = append(out, end, value)?;
    }
    if end > MAX_RESULT_LEN {
        return Err(Error::Invalid);
    }
    out[32..36].copy_from_slice(&(end as u32).to_le_bytes());
    decode_result(&out[..end])?;
    Ok(end)
}
fn append(out: &mut [u8], offset: usize, value: &[u8]) -> Result<usize, Error> {
    let end = offset.checked_add(2 + value.len()).ok_or(Error::Invalid)?;
    let target = out.get_mut(offset..end).ok_or(Error::Buffer)?;
    target[..2].copy_from_slice(&(value.len() as u16).to_le_bytes());
    target[2..].copy_from_slice(value);
    Ok(end)
}
pub fn encode_failure(
    kind: Kind,
    status: i32,
    question: Name<'_>,
    out: &mut [u8],
) -> Result<usize, Error> {
    if status >= 0 {
        return Err(Error::Invalid);
    }
    encode_result(
        kind,
        status,
        question,
        None,
        false,
        core::iter::empty(),
        core::iter::empty(),
        out,
    )
}

#[derive(Clone, Copy)]
pub struct Values<'a> {
    bytes: &'a [u8],
    count: usize,
}
impl<'a> Iterator for Values<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        let n = usize::from(u16_at(self.bytes, 0).ok()?);
        let data = self.bytes.get(2..2 + n)?;
        self.bytes = self.bytes.get(2 + n..)?;
        self.count -= 1;
        Some(data)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.count, Some(self.count))
    }
}
impl ExactSizeIterator for Values<'_> {}

pub struct ResultView<'a> {
    pub kind: Kind,
    pub status: i32,
    pub question: Name<'a>,
    pub canonical: Option<Name<'a>>,
    pub cached: bool,
    aliases: Values<'a>,
    values: Values<'a>,
}
impl<'a> ResultView<'a> {
    pub fn aliases(&self) -> Values<'a> {
        self.aliases
    }
    pub fn values(&self) -> Values<'a> {
        self.values
    }
}
pub fn decode_result(bytes: &[u8]) -> Result<ResultView<'_>, Error> {
    if bytes.len() < RESULT_HEADER_LEN
        || bytes.len() > MAX_RESULT_LEN
        || bytes[..8] != *b"NDNSRSLT"
        || u16_at(bytes, 8)? != 1
        || bytes[30..32] != [0; 2]
        || bytes[36..40] != [0; 4]
        || u32_at(bytes, 32)? as usize != bytes.len()
    {
        return Err(Error::Invalid);
    }
    let kind = Kind::decode(u16_at(bytes, 10)?)?;
    let status = u32_at(bytes, 12)? as i32;
    let cached = u32_at(bytes, 16)?;
    let count = u32_at(bytes, 20)? as usize;
    let alias_count = usize::from(u16_at(bytes, 28)?);
    if status > 0
        || status == i32::MIN
        || cached > 1
        || count > MAX_RECORDS
        || alias_count > MAX_ALIASES
    {
        return Err(Error::Invalid);
    }
    let question_end = RESULT_HEADER_LEN + usize::from(u16_at(bytes, 24)?);
    let canonical_end = question_end + usize::from(u16_at(bytes, 26)?);
    let question = Name::decode(
        bytes
            .get(RESULT_HEADER_LEN..question_end)
            .ok_or(Error::Invalid)?,
    )?;
    let canonical = if status == 0 {
        Some(Name::decode(
            bytes
                .get(question_end..canonical_end)
                .ok_or(Error::Invalid)?,
        )?)
    } else {
        if question_end != canonical_end || count != 0 || alias_count != 0 || cached != 0 {
            return Err(Error::Invalid);
        }
        None
    };
    let mut end = canonical_end;
    for _ in 0..alias_count {
        let (n, next) = entry(bytes, end)?;
        Name::decode(n)?;
        end = next;
    }
    let alias_end = end;
    for _ in 0..count {
        let (n, next) = entry(bytes, end)?;
        value_valid(kind, n)?;
        end = next;
    }
    if end != bytes.len() {
        return Err(Error::Invalid);
    }
    let aliases = Values {
        bytes: &bytes[canonical_end..alias_end],
        count: alias_count,
    };
    if let Some(canonical) = canonical {
        if alias_count == 0 && !question.matches(canonical) {
            return Err(Error::Invalid);
        }
        let mut seen = aliases;
        for index in 0..alias_count {
            let name = Name::decode(seen.next().ok_or(Error::Invalid)?)?;
            if index == 0 && !name.matches(question) || name.matches(canonical) {
                return Err(Error::Invalid);
            }
            for previous in aliases.take(index) {
                if name.matches(Name::decode(previous)?) {
                    return Err(Error::Invalid);
                }
            }
        }
    }
    Ok(ResultView {
        kind,
        status,
        question,
        canonical,
        cached: cached == 1,
        aliases,
        values: Values {
            bytes: &bytes[alias_end..],
            count,
        },
    })
}
fn entry(bytes: &[u8], offset: usize) -> Result<(&[u8], usize), Error> {
    let length = usize::from(u16_at(bytes, offset)?);
    let end = offset.checked_add(2 + length).ok_or(Error::Invalid)?;
    Ok((bytes.get(offset + 2..end).ok_or(Error::Invalid)?, end))
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(Error::Invalid)?
            .try_into()
            .map_err(|_| Error::Invalid)?,
    ))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::Invalid)?
            .try_into()
            .map_err(|_| Error::Invalid)?,
    ))
}
