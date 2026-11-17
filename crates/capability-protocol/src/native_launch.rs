//! Measured system launchers request a prepared, stopped native process.
//! Bindings refer to IPC attachment positions, never sender Handle numbers.
//! The launcher installs its POSIX state before resuming the returned owner.
use crate::{ProtocolError as Error, application_launch as text};

pub const OPCODE: u32 = u32::from_le_bytes(*b"MNL1");
pub const HEADER: usize = 24;
pub const MAX_BYTES: usize = 1024;
pub const MAX_HANDLES: usize = 4;
pub const MAX_VALUES: usize = 16;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Binding {
    pub key: u64,
    pub rights: u64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Value {
    pub key: u64,
    pub value: u64,
}

pub struct Request<'a> {
    pub class: u64,
    pub text: text::Request<'a>,
    pub bindings: &'a [Binding],
    pub values: &'a [Value],
}
pub struct Decoded<'a> {
    pub class: u64,
    pub text: text::Decoded<'a>,
    bindings: &'a [u8],
    values: &'a [u8],
}
impl Decoded<'_> {
    pub fn bindings(&self) -> impl Iterator<Item = Binding> + '_ {
        self.bindings.chunks_exact(16).map(|b| Binding {
            key: u64::from_le_bytes(b[..8].try_into().unwrap()),
            rights: u64::from_le_bytes(b[8..].try_into().unwrap()),
        })
    }
    pub fn values(&self) -> impl Iterator<Item = Value> + '_ {
        self.values.chunks_exact(16).map(|b| Value {
            key: u64::from_le_bytes(b[..8].try_into().unwrap()),
            value: u64::from_le_bytes(b[8..].try_into().unwrap()),
        })
    }
}
pub fn encode(request: &Request<'_>, output: &mut [u8]) -> Result<usize, Error> {
    if !matches!(request.class, 2 | 3)
        || request.bindings.len() > MAX_HANDLES
        || request.values.len() > MAX_VALUES
        || request.text.stdio_metadata != [0; 3]
    {
        return Err(Error::InvalidField);
    }
    let offset = HEADER + 16 * (request.bindings.len() + request.values.len());
    let limit = output.len().min(MAX_BYTES);
    let output = &mut output[..limit];
    let length = text::encode(
        &request.text,
        output.get_mut(offset..).ok_or(Error::InvalidLength)?,
    )?;
    output[..HEADER].fill(0);
    output[..4].copy_from_slice(&OPCODE.to_le_bytes());
    output[4..8].copy_from_slice(&1u32.to_le_bytes());
    output[8..16].copy_from_slice(&request.class.to_le_bytes());
    output[16..18].copy_from_slice(&(request.bindings.len() as u16).to_le_bytes());
    output[18..20].copy_from_slice(&(request.values.len() as u16).to_le_bytes());
    for (b, (key, value)) in output[HEADER..offset].chunks_exact_mut(16).zip(
        request
            .bindings
            .iter()
            .map(|b| (b.key, b.rights))
            .chain(request.values.iter().map(|v| (v.key, v.value))),
    ) {
        b[..8].copy_from_slice(&key.to_le_bytes());
        b[8..].copy_from_slice(&value.to_le_bytes());
    }
    let length = offset + length;
    decode(&output[..length])?;
    Ok(length)
}
pub fn decode(bytes: &[u8]) -> Result<Decoded<'_>, Error> {
    if bytes.len() < HEADER || bytes.len() > MAX_BYTES {
        return Err(Error::InvalidLength);
    }
    if bytes[..4] != OPCODE.to_le_bytes() {
        return Err(Error::UnknownOpcode);
    }
    if bytes[4..8] != 1u32.to_le_bytes() {
        return Err(Error::UnsupportedVersion);
    }
    let class = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let handles = u16::from_le_bytes(bytes[16..18].try_into().unwrap()) as usize;
    let values = u16::from_le_bytes(bytes[18..20].try_into().unwrap()) as usize;
    if !matches!(class, 2 | 3)
        || handles > MAX_HANDLES
        || values > MAX_VALUES
        || bytes[20..HEADER] != [0; 4]
    {
        return Err(Error::InvalidField);
    }
    let split = HEADER + 16 * handles;
    let end = split + 16 * values;
    let text = text::decode(bytes.get(end..).ok_or(Error::InvalidLength)?)?;
    if text.stdio_metadata != [0; 3] {
        return Err(Error::InvalidField);
    }
    let result = Decoded {
        class,
        text,
        bindings: &bytes[HEADER..split],
        values: &bytes[split..end],
    };
    for (i, binding) in result.bindings().enumerate() {
        if binding.rights == 0
            || result
                .bindings()
                .take(i)
                .any(|previous| previous.key == binding.key)
        {
            return Err(Error::InvalidField);
        }
    }
    for (i, value) in result.values().enumerate() {
        if result
            .values()
            .take(i)
            .any(|previous| previous.key == value.key)
        {
            return Err(Error::InvalidField);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_attachment_positions_and_opaque_values() {
        let mut bytes = [0; MAX_BYTES];
        let bindings = [Binding { key: 9, rights: 16 }];
        let values = [Value { key: 9, value: 123 }];
        let mut request = Request {
            class: 2,
            text: text::Request {
                path: "/system/services/input.service",
                arguments: &["input.service", ""],
                environment: &["LANG=ja_JP"],
                stdio_metadata: [0; 3],
            },
            bindings: &bindings,
            values: &values,
        };
        let n = encode(&request, &mut bytes).unwrap();
        let decoded = decode(&bytes[..n]).unwrap();
        assert_eq!(decoded.bindings().collect::<alloc::vec::Vec<_>>(), bindings);
        assert_eq!(decoded.values().collect::<alloc::vec::Vec<_>>(), values);
        assert_eq!(
            decoded
                .text
                .arguments
                .iter()
                .collect::<alloc::vec::Vec<_>>(),
            ["input.service", ""]
        );
        for at in [4, 20, 23] {
            let mut bad = bytes;
            bad[at] ^= 1;
            assert!(decode(&bad[..n]).is_err());
        }
        assert!(decode(&bytes[..n - 1]).is_err());
        assert!(decode(&bytes[..n + 1]).is_err());
        let duplicate = [bindings[0]; 2];
        request.bindings = &duplicate;
        assert!(encode(&request, &mut bytes).is_err());
        let empty = [Binding { rights: 0, ..bindings[0] }];
        request.bindings = &empty;
        assert!(encode(&request, &mut bytes).is_err());
    }
}
