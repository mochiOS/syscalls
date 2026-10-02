#![no_std]

pub const MAGIC: [u8; 4] = *b"MPKS";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 24;
pub const MAX_MESSAGE_LEN: usize = 64 * 1024;
pub const MAX_PATH_LEN: usize = 4095;
pub const MAX_PACKAGE_ID_LEN: usize = 128;
pub const MAX_NAME_LEN: usize = 255;
pub const MAX_VERSION_LEN: usize = 128;
pub const MAX_KIND_LEN: usize = 32;
pub const MAX_PACKAGES: usize = 1024;

pub const OP_INSTALL: u16 = 1;
pub const OP_UPDATE: u16 = 2;
pub const OP_REMOVE: u16 = 3;
pub const OP_LIST: u16 = 4;
pub const OP_STATUS: u16 = 0x8000;
pub const OP_LIST_RESULT: u16 = 0x8004;

pub const PACKAGE_FLAG_BUILT_IN: u32 = 1 << 0;
pub const PACKAGE_FLAG_REMOVABLE: u32 = 1 << 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    BufferTooSmall,
    InvalidMagic,
    UnsupportedVersion,
    InvalidLength,
    InvalidField,
    UnexpectedOpcode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message<'a> {
    pub opcode: u16,
    pub request_id: u64,
    /// Zero on success, otherwise a negative errno value.
    pub status: i32,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Install(&'a str),
    Update(&'a str),
    Remove(&'a str),
    List,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackageRecord<'a> {
    pub package_id: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    pub kind: &'a str,
    pub flags: u32,
}

pub fn encode_request(
    request_id: u64,
    request: Request<'_>,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let (opcode, payload) = match request {
        Request::Install(path) => {
            validate_path(path)?;
            (OP_INSTALL, path.as_bytes())
        }
        Request::Update(path) => {
            validate_path(path)?;
            (OP_UPDATE, path.as_bytes())
        }
        Request::Remove(package_id) => {
            validate_package_id(package_id)?;
            (OP_REMOVE, package_id.as_bytes())
        }
        Request::List => (OP_LIST, &[][..]),
    };
    encode_message(opcode, request_id, 0, payload, output)
}

pub fn decode_request(bytes: &[u8]) -> Result<(u64, Request<'_>), ProtocolError> {
    let message = decode_message(bytes)?;
    if message.status != 0 {
        return Err(ProtocolError::InvalidField);
    }
    let request = match message.opcode {
        OP_INSTALL => {
            let path = decode_text(message.payload)?;
            validate_path(path)?;
            Request::Install(path)
        }
        OP_UPDATE => {
            let path = decode_text(message.payload)?;
            validate_path(path)?;
            Request::Update(path)
        }
        OP_REMOVE => {
            let package_id = decode_text(message.payload)?;
            validate_package_id(package_id)?;
            Request::Remove(package_id)
        }
        OP_LIST if message.payload.is_empty() => Request::List,
        OP_LIST => return Err(ProtocolError::InvalidLength),
        _ => return Err(ProtocolError::UnexpectedOpcode),
    };
    Ok((message.request_id, request))
}

pub fn encode_status(
    request_id: u64,
    status: i32,
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    encode_message(OP_STATUS, request_id, status, &[], output)
}

pub fn decode_status(bytes: &[u8], request_id: u64) -> Result<i32, ProtocolError> {
    let message = decode_message(bytes)?;
    if message.opcode != OP_STATUS
        || message.request_id != request_id
        || !message.payload.is_empty()
    {
        return Err(ProtocolError::InvalidField);
    }
    Ok(message.status)
}

pub struct ListEncoder<'a> {
    output: &'a mut [u8],
    request_id: u64,
    length: usize,
    count: u32,
}

impl<'a> ListEncoder<'a> {
    pub fn new(request_id: u64, output: &'a mut [u8]) -> Result<Self, ProtocolError> {
        if output.len() < HEADER_LEN + 4 {
            return Err(ProtocolError::BufferTooSmall);
        }
        output[HEADER_LEN..HEADER_LEN + 4].fill(0);
        Ok(Self {
            output,
            request_id,
            length: HEADER_LEN + 4,
            count: 0,
        })
    }

    pub fn push(&mut self, record: PackageRecord<'_>) -> Result<(), ProtocolError> {
        validate_package_id(record.package_id)?;
        validate_text(record.name, MAX_NAME_LEN, false)?;
        validate_text(record.version, MAX_VERSION_LEN, false)?;
        validate_text(record.kind, MAX_KIND_LEN, true)?;
        if self.count as usize >= MAX_PACKAGES {
            return Err(ProtocolError::InvalidLength);
        }
        let fields = [
            record.package_id.as_bytes(),
            record.name.as_bytes(),
            record.version.as_bytes(),
            record.kind.as_bytes(),
        ];
        let record_len = 12usize
            .checked_add(fields.iter().map(|field| field.len()).sum::<usize>())
            .ok_or(ProtocolError::InvalidLength)?;
        let end = self
            .length
            .checked_add(record_len)
            .ok_or(ProtocolError::InvalidLength)?;
        if end > self.output.len() || end > MAX_MESSAGE_LEN {
            return Err(ProtocolError::BufferTooSmall);
        }
        self.output[self.length..self.length + 4].copy_from_slice(&record.flags.to_le_bytes());
        for (index, field) in fields.iter().enumerate() {
            let length = u16::try_from(field.len()).map_err(|_| ProtocolError::InvalidLength)?;
            let offset = self.length + 4 + index * 2;
            self.output[offset..offset + 2].copy_from_slice(&length.to_le_bytes());
        }
        let mut cursor = self.length + 12;
        for field in fields {
            self.output[cursor..cursor + field.len()].copy_from_slice(field);
            cursor += field.len();
        }
        self.length = end;
        self.count += 1;
        Ok(())
    }

    pub fn finish(self) -> Result<usize, ProtocolError> {
        self.output[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&self.count.to_le_bytes());
        encode_header(
            OP_LIST_RESULT,
            self.request_id,
            0,
            self.length - HEADER_LEN,
            &mut self.output[..self.length],
        )?;
        Ok(self.length)
    }
}

pub struct PackageRecords<'a> {
    payload: &'a [u8],
    remaining: usize,
}

impl<'a> Iterator for PackageRecords<'a> {
    type Item = Result<PackageRecord<'a>, ProtocolError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            if !self.payload.is_empty() {
                self.payload = &[];
                return Some(Err(ProtocolError::InvalidLength));
            }
            return None;
        }
        if self.payload.len() < 12 {
            self.remaining = 0;
            return Some(Err(ProtocolError::InvalidLength));
        }
        let flags = u32::from_le_bytes(self.payload[..4].try_into().unwrap());
        let lengths = [
            u16::from_le_bytes(self.payload[4..6].try_into().unwrap()) as usize,
            u16::from_le_bytes(self.payload[6..8].try_into().unwrap()) as usize,
            u16::from_le_bytes(self.payload[8..10].try_into().unwrap()) as usize,
            u16::from_le_bytes(self.payload[10..12].try_into().unwrap()) as usize,
        ];
        let total = match lengths
            .iter()
            .try_fold(12usize, |total, length| total.checked_add(*length))
        {
            Some(total) if total <= self.payload.len() => total,
            _ => {
                self.remaining = 0;
                return Some(Err(ProtocolError::InvalidLength));
            }
        };
        let mut cursor = 12;
        let mut take = |length: usize| {
            let field = decode_text(&self.payload[cursor..cursor + length]);
            cursor += length;
            field
        };
        let result = (|| {
            let package_id = take(lengths[0])?;
            let name = take(lengths[1])?;
            let version = take(lengths[2])?;
            let kind = take(lengths[3])?;
            validate_package_id(package_id)?;
            validate_text(name, MAX_NAME_LEN, false)?;
            validate_text(version, MAX_VERSION_LEN, false)?;
            validate_text(kind, MAX_KIND_LEN, true)?;
            Ok(PackageRecord {
                package_id,
                name,
                version,
                kind,
                flags,
            })
        })();
        self.payload = &self.payload[total..];
        self.remaining -= 1;
        Some(result)
    }
}

pub fn decode_list(bytes: &[u8], request_id: u64) -> Result<PackageRecords<'_>, ProtocolError> {
    let message = decode_message(bytes)?;
    if message.opcode != OP_LIST_RESULT
        || message.request_id != request_id
        || message.status != 0
        || message.payload.len() < 4
    {
        return Err(ProtocolError::InvalidField);
    }
    let count = u32::from_le_bytes(message.payload[..4].try_into().unwrap()) as usize;
    if count > MAX_PACKAGES {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(PackageRecords {
        payload: &message.payload[4..],
        remaining: count,
    })
}

fn encode_message(
    opcode: u16,
    request_id: u64,
    status: i32,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let total = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(ProtocolError::InvalidLength)?;
    if total > output.len() || total > MAX_MESSAGE_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    encode_header(
        opcode,
        request_id,
        status,
        payload.len(),
        &mut output[..total],
    )?;
    output[HEADER_LEN..total].copy_from_slice(payload);
    Ok(total)
}

fn encode_header(
    opcode: u16,
    request_id: u64,
    status: i32,
    payload_len: usize,
    output: &mut [u8],
) -> Result<(), ProtocolError> {
    if output.len() < HEADER_LEN || payload_len > u32::MAX as usize {
        return Err(ProtocolError::BufferTooSmall);
    }
    output[..4].copy_from_slice(&MAGIC);
    output[4..6].copy_from_slice(&VERSION.to_le_bytes());
    output[6..8].copy_from_slice(&opcode.to_le_bytes());
    output[8..16].copy_from_slice(&request_id.to_le_bytes());
    output[16..20].copy_from_slice(&status.to_le_bytes());
    output[20..24].copy_from_slice(&(payload_len as u32).to_le_bytes());
    Ok(())
}

fn decode_message(bytes: &[u8]) -> Result<Message<'_>, ProtocolError> {
    if bytes.len() < HEADER_LEN || bytes.len() > MAX_MESSAGE_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    if bytes[..4] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    if u16::from_le_bytes(bytes[4..6].try_into().unwrap()) != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    let payload_len = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
    if HEADER_LEN.checked_add(payload_len) != Some(bytes.len()) {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(Message {
        opcode: u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
        request_id: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        status: i32::from_le_bytes(bytes[16..20].try_into().unwrap()),
        payload: &bytes[HEADER_LEN..],
    })
}

fn decode_text(bytes: &[u8]) -> Result<&str, ProtocolError> {
    if bytes.contains(&0) {
        return Err(ProtocolError::InvalidField);
    }
    core::str::from_utf8(bytes).map_err(|_| ProtocolError::InvalidField)
}

fn validate_path(path: &str) -> Result<(), ProtocolError> {
    if path.is_empty()
        || path.len() > MAX_PATH_LEN
        || !path.starts_with('/')
        || path == "/"
        || path.ends_with('/')
        || path.contains("//")
        || path.contains('\0')
        || path.contains('\\')
        || path[1..]
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(ProtocolError::InvalidField);
    }
    Ok(())
}

fn validate_package_id(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_PACKAGE_ID_LEN
        || value == "."
        || value == ".."
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')))
    {
        return Err(ProtocolError::InvalidField);
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize, allow_empty: bool) -> Result<(), ProtocolError> {
    if (!allow_empty && value.is_empty())
        || value.len() > maximum
        || value.chars().any(char::is_control)
    {
        return Err(ProtocolError::InvalidField);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_and_reject_trailing_bytes() {
        let mut bytes = [0u8; 128];
        let len = encode_request(42, Request::Install("/tmp/a.mpkg"), &mut bytes).unwrap();
        assert_eq!(
            decode_request(&bytes[..len]),
            Ok((42, Request::Install("/tmp/a.mpkg")))
        );
        assert_eq!(
            decode_request(&bytes[..len + 1]),
            Err(ProtocolError::InvalidLength)
        );
        assert_eq!(
            encode_request(1, Request::Install("/tmp/../bad.mpkg"), &mut bytes),
            Err(ProtocolError::InvalidField)
        );
    }

    #[test]
    fn package_list_round_trips() {
        let mut bytes = [0u8; 512];
        let mut encoder = ListEncoder::new(7, &mut bytes).unwrap();
        encoder
            .push(PackageRecord {
                package_id: "org.mochios.edit",
                name: "Edit",
                version: "1.2.3",
                kind: "application",
                flags: PACKAGE_FLAG_REMOVABLE,
            })
            .unwrap();
        let len = encoder.finish().unwrap();
        let mut records = decode_list(&bytes[..len], 7).unwrap();
        assert_eq!(records.next().unwrap().unwrap().name, "Edit");
        assert!(records.next().is_none());
    }
}
