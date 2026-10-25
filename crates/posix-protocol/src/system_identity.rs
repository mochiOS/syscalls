//! Bounded byte strings on the wire; no C pointers or struct utsname padding.
pub const FIELD_CAPACITY: usize = 256;
pub const HOST_NAME_MAX: usize = FIELD_CAPACITY - 1;
pub const FIELD_COUNT: usize = 5;
pub const MAX_RECORD: usize = FIELD_COUNT * (2 + HOST_NAME_MAX);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub system: &'a [u8],
    pub node: &'a [u8],
    pub release: &'a [u8],
    pub version: &'a [u8],
    pub machine: &'a [u8],
}

pub fn valid_field(value: &[u8]) -> bool {
    value.len() < FIELD_CAPACITY && !value.contains(&0)
}

pub fn encode(record: Record<'_>, output: &mut [u8]) -> Result<usize, ()> {
    let fields = [
        record.system,
        record.node,
        record.release,
        record.version,
        record.machine,
    ];
    if fields.iter().any(|field| !valid_field(field)) {
        return Err(());
    }
    let size = fields.iter().map(|field| 2 + field.len()).sum();
    if output.len() < size {
        return Err(());
    }
    let mut position = 0;
    for field in fields {
        output[position..position + 2].copy_from_slice(&(field.len() as u16).to_le_bytes());
        position += 2;
        output[position..position + field.len()].copy_from_slice(field);
        position += field.len();
    }
    Ok(position)
}

pub fn decode(bytes: &[u8]) -> Result<Record<'_>, ()> {
    fn field<'a>(bytes: &mut &'a [u8]) -> Result<&'a [u8], ()> {
        let size = u16::from_le_bytes(bytes.get(..2).ok_or(())?.try_into().unwrap()) as usize;
        let text = bytes.get(2..2 + size).ok_or(())?;
        if !valid_field(text) {
            return Err(());
        }
        *bytes = &bytes[2 + size..];
        Ok(text)
    }
    let mut rest = bytes;
    let result = Record {
        system: field(&mut rest)?,
        node: field(&mut rest)?,
        release: field(&mut rest)?,
        version: field(&mut rest)?,
        machine: field(&mut rest)?,
    };
    if !rest.is_empty() {
        return Err(());
    }
    Ok(result)
}
