//! C resolver packet compatibility over scoped, validated native snapshots.
//! Replies are reconstructed (not raw server packets), with TTL zero because
//! snapshot v1 does not expose a remaining per-record lifetime or DNSSEC proof.
//! RA is also left clear: availability of server recursion is not in a snapshot.
use crate::resolver::{Kind, ResultView};

/// A malformed message, unsupported result, or insufficient destination space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Buffer,
}

/// Expand a compressed DNS name into presentation text without a terminator.
/// Returns (bytes consumed at `start`, output length). Pointer targets must
/// precede their containing name; the decreasing ceiling rejects cycles.
/// Labels retain their case and binary octets use decimal DNS escapes.
pub fn expand(packet: &[u8], start: usize, output: &mut [u8]) -> Result<(usize, usize), Error> {
    if packet.len() > 65535 || start >= packet.len() {
        return Err(Error::Invalid);
    }
    let mut wire = [0; 255];
    let (mut offset, mut length, mut consumed, mut ceiling) = (start, 0, None, start);
    loop {
        let n = usize::from(*packet.get(offset).ok_or(Error::Invalid)?);
        if n & 0xc0 == 0xc0 {
            let low = usize::from(*packet.get(offset + 1).ok_or(Error::Invalid)?);
            let target = ((n & 63) << 8) | low;
            if target < 12 || target >= ceiling || target >= offset {
                return Err(Error::Invalid);
            }
            ceiling = target;
            consumed.get_or_insert(offset + 2 - start);
            offset = target;
            continue;
        }
        if n > 63 || length + n + 1 > wire.len() {
            return Err(Error::Invalid);
        }
        let label = packet.get(offset..offset + 1 + n).ok_or(Error::Invalid)?;
        wire[length..length + label.len()].copy_from_slice(label);
        length += label.len();
        offset += label.len();
        if n == 0 {
            break;
        }
    }
    // An empty string is the historical dn_expand spelling of the root.
    let mut used = 0;
    let mut offset_wire = 0;
    while wire[offset_wire] != 0 {
        if offset_wire != 0 {
            put(output, &mut used, b'.')?;
        }
        let n = usize::from(wire[offset_wire]);
        for &byte in &wire[offset_wire + 1..offset_wire + 1 + n] {
            match byte {
                b'.' | b'\\' | b'"' | b';' | b'(' | b')' | b'@' | b'$' => {
                    put(output, &mut used, b'\\')?;
                    put(output, &mut used, byte)?;
                }
                0x21..=0x7e => put(output, &mut used, byte)?,
                _ => {
                    for byte in [
                        b'\\',
                        b'0' + byte / 100,
                        b'0' + byte / 10 % 10,
                        b'0' + byte % 10,
                    ] {
                        put(output, &mut used, byte)?;
                    }
                }
            }
        }
        offset_wire += 1 + n;
    }
    Ok((consumed.unwrap_or(offset - start), used))
}
fn put(out: &mut [u8], used: &mut usize, byte: u8) -> Result<(), Error> {
    *out.get_mut(*used).ok_or(Error::Buffer)? = byte;
    *used += 1;
    Ok(())
}

/// Encode a positive native snapshot as an IN-class DNS reply.
/// Returns the complete required size. A smaller output receives a truncated
/// prefix with TC set, allowing res_query callers to resize and retry.
/// Unsupported/failed snapshots and messages larger than 65535 are rejected.
pub fn reply(result: &ResultView<'_>, out: &mut [u8]) -> Result<usize, Error> {
    if result.status != 0 || result.values().len() == 0 {
        return Err(Error::Invalid);
    }
    let canonical = result.canonical.ok_or(Error::Invalid)?.bytes();
    let aliases = result.aliases();
    let count = aliases
        .len()
        .checked_add(result.values().len())
        .filter(|n| *n <= 65535)
        .ok_or(Error::Invalid)?;
    let mut length = 12 + result.question.bytes().len() + 4;
    let mut iter = result.aliases();
    while let Some(owner) = iter.next() {
        let target = iter.clone().next().unwrap_or(canonical);
        length = length
            .checked_add(owner.len() + 10 + target.len())
            .ok_or(Error::Invalid)?;
    }
    for value in result.values() {
        length = length
            .checked_add(canonical.len() + 10 + value.len())
            .ok_or(Error::Invalid)?;
    }
    if length > 65535 {
        return Err(Error::Invalid);
    }
    let truncated = length > out.len();
    let mut cursor = 0;
    let mut write = |bytes: &[u8]| {
        let n = out.len().saturating_sub(cursor).min(bytes.len());
        if n != 0 {
            out[cursor..cursor + n].copy_from_slice(&bytes[..n]);
        }
        cursor += bytes.len();
    };
    let mut header = [0; 12];
    header[2..4].copy_from_slice(&(0x8100u16 | if truncated { 0x0200 } else { 0 }).to_be_bytes());
    header[4..6].copy_from_slice(&1u16.to_be_bytes());
    header[6..8].copy_from_slice(&(count as u16).to_be_bytes());
    write(&header);
    write(result.question.bytes());
    write(&(result.kind as u16).to_be_bytes());
    write(&1u16.to_be_bytes());
    let mut records = result.aliases();
    while let Some(owner) = records.next() {
        let target = records.clone().next().unwrap_or(canonical);
        record(&mut write, owner, 5, target);
    }
    for value in result.values() {
        record(&mut write, canonical, result.kind as u16, value);
    }
    Ok(length)
}
fn record(write: &mut impl FnMut(&[u8]), owner: &[u8], kind: u16, value: &[u8]) {
    write(owner);
    write(&kind.to_be_bytes());
    write(&1u16.to_be_bytes());
    write(&0u32.to_be_bytes());
    write(&(value.len() as u16).to_be_bytes());
    write(value);
}

/// Decode the supported query kind. DNS class must be IN (1); ANY and zone
/// transfers are deliberately outside the scoped resolver contract.
pub fn query_kind(class: i32, kind: i32) -> Result<Kind, Error> {
    if class != 1 {
        return Err(Error::Invalid);
    }
    Kind::decode(u16::try_from(kind).map_err(|_| Error::Invalid)?).map_err(|_| Error::Invalid)
}
