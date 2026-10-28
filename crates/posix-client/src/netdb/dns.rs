//! DNS presentation/wire boundary, preserving label boundaries and escaped
//! bytes rather than treating a DNS name as a C string or UTF-8 hostname.
use super::{Address, Error, ScopedAddress};
use crate::resolver::Name;

/// DNS/service result status is distinct from a native Handle failure. System
/// carries a negative POSIX status for the libc boundary's errno conversion.
pub fn status(value: i32) -> Result<(), Error> {
    match value {
        0 => Ok(()),
        -2 => Err(Error::NoName),
        -11 | -110 => Err(Error::Again),
        -12 => Err(Error::Memory),
        -22 | -95 => Err(Error::Fail),
        value if value < 0 && value != i32::MIN => Err(Error::System(value)),
        _ => Err(Error::Fail),
    }
}

pub fn forward(
    result: &crate::resolver::ResultView<'_>,
    emit: &mut dyn FnMut(super::Host<'_>) -> Result<(), Error>,
) -> Result<usize, Error> {
    status(result.status)?;
    if !matches!(
        result.kind,
        crate::resolver::Kind::A | crate::resolver::Kind::Aaaa
    ) {
        return Err(Error::Fail);
    }
    let mut canonical = [0; super::NI_MAXHOST];
    let n = presentation(result.canonical.ok_or(Error::Fail)?, &mut canonical)?;
    let mut count = 0;
    for bytes in result.values() {
        let family = if result.kind == crate::resolver::Kind::A {
            super::AF_INET
        } else {
            super::AF_INET6
        };
        let address = Address::from_octets(family, bytes).map_err(|_| Error::Fail)?;
        emit(super::Host {
            address: address.into(),
            canonical: Some(&canonical[..n]),
        })?;
        count += 1;
    }
    Ok(count)
}
pub fn ptr(
    result: &crate::resolver::ResultView<'_>,
    out: &mut [u8],
) -> Result<Option<usize>, Error> {
    status(result.status)?;
    if result.kind != crate::resolver::Kind::Ptr {
        return Err(Error::Fail);
    }
    result
        .values()
        .next()
        .map(|bytes| presentation(Name::decode(bytes).map_err(|_| Error::Fail)?, out))
        .transpose()
}

pub fn question<'a>(text: &[u8], out: &'a mut [u8; 255]) -> Result<Name<'a>, Error> {
    if text == b"." {
        out[0] = 0;
        return Name::decode(&out[..1]).map_err(|_| Error::NoName);
    }
    if text.is_empty() {
        return Err(Error::NoName);
    }
    let mut source = 0;
    let mut length = 1;
    let mut label = 0;
    while source < text.len() {
        let mut byte = text[source];
        source += 1;
        if byte == b'.' {
            let n = length - label - 1;
            if n == 0 || n > 63 {
                return Err(Error::NoName);
            }
            out[label] = n as u8;
            if source == text.len() {
                break;
            }
            label = length;
            length += 1;
            if length >= 255 {
                return Err(Error::NoName);
            }
            continue;
        }
        if byte == b'\\' {
            byte = *text.get(source).ok_or(Error::NoName)?;
            source += 1;
            if byte.is_ascii_digit() {
                let digits = text.get(source - 1..source + 2).ok_or(Error::NoName)?;
                byte = super::decimal(digits)
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or(Error::NoName)?;
                source += 2;
            }
        } else if byte == 0 {
            return Err(Error::NoName);
        }
        if length >= 254 || length - label > 63 {
            return Err(Error::NoName);
        }
        out[length] = byte;
        length += 1;
    }
    let n = length - label - 1;
    if n == 0 || n > 63 {
        return Err(Error::NoName);
    }
    out[label] = n as u8;
    out[length] = 0;
    length += 1;
    Name::decode(&out[..length]).map_err(|_| Error::NoName)
}
pub fn presentation(name: Name<'_>, out: &mut [u8]) -> Result<usize, Error> {
    let mut at = 0;
    let mut written = 0;
    let mut put = |byte| {
        let slot = out.get_mut(written).ok_or(Error::Overflow)?;
        *slot = byte;
        written += 1;
        Ok::<(), Error>(())
    };
    if name.bytes() == [0] {
        put(b'.')?;
        return Ok(1);
    }
    while name.bytes()[at] != 0 {
        if at != 0 {
            put(b'.')?;
        }
        let length = usize::from(name.bytes()[at]);
        at += 1;
        for byte in &name.bytes()[at..at + length] {
            match byte {
                b'.' | b'\\' => {
                    put(b'\\')?;
                    put(*byte)?;
                }
                33..=126 => put(*byte)?,
                byte => {
                    put(b'\\')?;
                    put(b'0' + byte / 100)?;
                    put(b'0' + byte / 10 % 10)?;
                    put(b'0' + byte % 10)?;
                }
            }
        }
        at += length;
    }
    drop(put);
    Ok(written)
}
pub fn reverse<'a>(address: ScopedAddress, out: &'a mut [u8; 255]) -> Result<Name<'a>, Error> {
    let mut text = [0; 128];
    let mut n = 0;
    match address.address {
        Address::V4(v4) => {
            for byte in v4.iter().rev() {
                n += super::number(u32::from(*byte), &mut text[n..])?;
                text[n] = b'.';
                n += 1;
            }
            text[n..n + 12].copy_from_slice(b"in-addr.arpa");
            n += 12;
        }
        Address::V6(v6) => {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for byte in v6.iter().rev() {
                text[n] = HEX[usize::from(byte & 15)];
                text[n + 1] = b'.';
                text[n + 2] = HEX[usize::from(byte >> 4)];
                text[n + 3] = b'.';
                n += 4;
            }
            text[n..n + 8].copy_from_slice(b"ip6.arpa");
            n += 8;
        }
    }
    question(&text[..n], out)
}
