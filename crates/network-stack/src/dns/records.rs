//! DNS message values, independent of host-name syntax and POSIX APIs.
use super::{DNS_HEADER_LEN, DNS_MAX_LABEL_LEN, DnsError, DnsName, DnsResponseCode};
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;

pub const DNS_MAX_WIRE_MESSAGE_LEN: usize = u16::MAX as usize;
pub const DNS_MAX_ALIAS_DEPTH: usize = 16;
const MAX_NAME_WIRE_LEN: usize = 255;

/// An uncompressed, absolute DNS name. Only ASCII case is folded; arbitrary
/// label octets and the root are valid (RFC 2181 section 11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRecordName(Vec<u8>);

impl DnsRecordName {
    pub fn from_wire(wire: &[u8]) -> Result<Self, DnsError> {
        if wire.len() > MAX_NAME_WIRE_LEN {
            return Err(DnsError::NameTooLong);
        }
        let mut offset = 0;
        let mut normalized = Vec::with_capacity(wire.len());
        loop {
            let length = *wire.get(offset).ok_or(DnsError::Truncated)?;
            if usize::from(length) > DNS_MAX_LABEL_LEN {
                return Err(DnsError::LabelTooLong);
            }
            normalized.push(length);
            offset += 1;
            if length == 0 {
                if offset != wire.len() {
                    return Err(DnsError::InvalidHeader);
                }
                return Ok(Self(normalized));
            }
            let end = offset + usize::from(length);
            let label = wire.get(offset..end).ok_or(DnsError::Truncated)?;
            normalized.extend(label.iter().map(u8::to_ascii_lowercase));
            offset = end;
        }
    }

    pub fn wire(&self) -> &[u8] {
        &self.0
    }

    /// Apply host-name rules only when a DNS consumer actually needs a host.
    pub fn hostname(&self) -> Result<DnsName, DnsError> {
        let mut text = String::new();
        let mut offset = 0;
        while self.0[offset] != 0 {
            let length = usize::from(self.0[offset]);
            offset += 1;
            if !text.is_empty() {
                text.push('.');
            }
            let label = &self.0[offset..offset + length];
            if label.iter().any(|byte| !byte.is_ascii() || *byte == b'.') {
                return Err(DnsError::InvalidCharacter);
            }
            for byte in label {
                text.push(char::from(*byte));
            }
            offset += length;
        }
        DnsName::parse(&text)
    }

    pub fn reverse_ipv4(address: [u8; 4]) -> Self {
        let mut wire = Vec::new();
        for byte in address.into_iter().rev() {
            let mut digits = [0; 3];
            let start = if byte >= 100 {
                0
            } else if byte >= 10 {
                1
            } else {
                2
            };
            digits[0] = b'0' + byte / 100;
            digits[1] = b'0' + (byte / 10) % 10;
            digits[2] = b'0' + byte % 10;
            wire.push((3 - start) as u8);
            wire.extend_from_slice(&digits[start..]);
        }
        wire.extend_from_slice(b"\x07in-addr\x04arpa\0");
        Self(wire)
    }

    pub fn reverse_ipv6(address: [u8; 16]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut wire = Vec::with_capacity(74);
        for byte in address.into_iter().rev() {
            wire.extend_from_slice(&[
                1,
                HEX[usize::from(byte & 15)],
                1,
                HEX[usize::from(byte >> 4)],
            ]);
        }
        wire.extend_from_slice(b"\x03ip6\x04arpa\0");
        Self(wire)
    }
}

impl From<&DnsName> for DnsRecordName {
    fn from(name: &DnsName) -> Self {
        let mut wire = Vec::with_capacity(name.as_str().len() + 2);
        for label in name.as_str().split('.') {
            wire.push(label.len() as u8);
            wire.extend_from_slice(label.as_bytes());
        }
        wire.push(0);
        Self(wire)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsRecordType {
    A = 1,
    Ptr = 12,
    Aaaa = 28,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsRecordValue {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Name(DnsRecordName),
}

/// All matching answer-section records, with CNAMEs followed irrespective of
/// packet order. Empty values mean no terminal record in this message, never a
/// successful negative-cache entry. DNSSEC validation is not performed here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRecordSet {
    question: DnsRecordName,
    kind: DnsRecordType,
    canonical_name: DnsRecordName,
    values: Vec<DnsRecordValue>,
    ttl_seconds: u32,
}

impl DnsRecordSet {
    pub fn question(&self) -> &DnsRecordName {
        &self.question
    }
    pub fn record_type(&self) -> DnsRecordType {
        self.kind
    }
    pub fn canonical_name(&self) -> &DnsRecordName {
        &self.canonical_name
    }
    pub fn values(&self) -> &[DnsRecordValue] {
        &self.values
    }
    /// Minimum TTL of every traversed alias and every member of the RRset.
    pub fn ttl_seconds(&self) -> u32 {
        self.ttl_seconds
    }

    pub(super) fn ipv4(name: &DnsName, address: [u8; 4], ttl: u32) -> Self {
        let question = DnsRecordName::from(name);
        Self {
            canonical_name: question.clone(),
            question,
            kind: DnsRecordType::A,
            values: alloc::vec![DnsRecordValue::Ipv4(address)],
            ttl_seconds: normalize_ttl(ttl),
        }
    }
}

pub fn encode_dns_record_query(
    transaction_id: u16,
    name: &DnsRecordName,
    kind: DnsRecordType,
    out: &mut [u8],
) -> Result<usize, DnsError> {
    let length = DNS_HEADER_LEN + name.0.len() + 4;
    let message = out.get_mut(..length).ok_or(DnsError::BufferTooSmall)?;
    message[..DNS_HEADER_LEN].fill(0);
    message[..2].copy_from_slice(&transaction_id.to_be_bytes());
    message[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
    message[4..6].copy_from_slice(&1u16.to_be_bytes());
    let question_end = DNS_HEADER_LEN + name.0.len();
    message[DNS_HEADER_LEN..question_end].copy_from_slice(&name.0);
    message[question_end..question_end + 2].copy_from_slice(&(kind as u16).to_be_bytes());
    message[question_end + 2..].copy_from_slice(&1u16.to_be_bytes());
    Ok(length)
}

enum RecordData {
    Value(DnsRecordType, DnsRecordValue),
    Alias(DnsRecordName),
    Other(u16),
}

struct Record {
    owner: DnsRecordName,
    data: RecordData,
    ttl: u32,
}

pub fn decode_dns_records(
    packet: &[u8],
    transaction_id: u16,
    expected_name: &DnsRecordName,
    kind: DnsRecordType,
) -> Result<DnsRecordSet, DnsError> {
    if packet.len() > DNS_MAX_WIRE_MESSAGE_LEN {
        return Err(DnsError::MessageTooLarge);
    }
    if packet.len() < DNS_HEADER_LEN {
        return Err(DnsError::Truncated);
    }
    if super::read_u16(packet, 0)? != transaction_id {
        return Err(DnsError::TransactionMismatch);
    }
    let flags = super::read_u16(packet, 2)?;
    // AD/CD are valid; the remaining reserved header bit is not.
    if flags & 0x8000 == 0 || flags & 0x7840 != 0 {
        return Err(DnsError::InvalidHeader);
    }
    if super::read_u16(packet, 4)? != 1 {
        return Err(DnsError::QuestionMismatch);
    }
    let (question, mut offset) = decode_record_name(packet, DNS_HEADER_LEN, packet.len())?;
    if question != *expected_name
        || super::read_u16(packet, offset)? != kind as u16
        || super::read_u16(packet, offset + 2)? != 1
    {
        return Err(DnsError::QuestionMismatch);
    }
    offset += 4;
    // A truncated UDP packet may omit part of its last RR. Check the question
    // first, then require a transport retry instead of using a prefix.
    if flags & 0x0200 != 0 {
        return Err(DnsError::TruncatedResponse);
    }
    let response_code = super::decode_response_code((flags & 15) as u8)?;
    let answers = usize::from(super::read_u16(packet, 6)?);
    let count = answers
        + usize::from(super::read_u16(packet, 8)?)
        + usize::from(super::read_u16(packet, 10)?);
    // Even an empty-data RR needs one root byte and ten fixed bytes.
    if count > packet.len().saturating_sub(offset) / 11 {
        return Err(DnsError::Truncated);
    }
    let mut records = Vec::new();
    for index in 0..count {
        let (owner, next) = decode_record_name(packet, offset, packet.len())?;
        let record_type = super::read_u16(packet, next)?;
        let class = super::read_u16(packet, next + 2)?;
        let ttl = normalize_ttl(super::read_u32(packet, next + 4)?);
        let length = usize::from(super::read_u16(packet, next + 8)?);
        let start = next + 10;
        let end = start.checked_add(length).ok_or(DnsError::Truncated)?;
        let data = packet.get(start..end).ok_or(DnsError::Truncated)?;
        let decoded = if class != 1 {
            RecordData::Other(record_type)
        } else {
            match record_type {
                1 => RecordData::Value(
                    DnsRecordType::A,
                    DnsRecordValue::Ipv4(
                        data.try_into().map_err(|_| DnsError::InvalidRecordLength)?,
                    ),
                ),
                28 => RecordData::Value(
                    DnsRecordType::Aaaa,
                    DnsRecordValue::Ipv6(
                        data.try_into().map_err(|_| DnsError::InvalidRecordLength)?,
                    ),
                ),
                5 | 12 => {
                    let (target, consumed) = decode_record_name(packet, start, end)?;
                    if consumed != end {
                        return Err(DnsError::InvalidRecordLength);
                    }
                    if record_type == 5 {
                        RecordData::Alias(target)
                    } else {
                        RecordData::Value(DnsRecordType::Ptr, DnsRecordValue::Name(target))
                    }
                }
                _ => RecordData::Other(record_type),
            }
        };
        // Authority/additional data is structurally checked, but cannot seed
        // an answer or poison this cache, even if its owner matches the query.
        if index < answers && class == 1 {
            records.push(Record {
                owner,
                data: decoded,
                ttl,
            });
        }
        offset = end;
    }
    if offset != packet.len() {
        return Err(DnsError::InvalidHeader);
    }
    if response_code != DnsResponseCode::NoError {
        return Err(DnsError::Response(response_code));
    }

    let mut canonical = expected_name.clone();
    let mut visited = Vec::new();
    let mut ttl = None::<u32>;
    loop {
        if visited.contains(&canonical) {
            return Err(DnsError::AliasLoop);
        }
        visited.push(canonical.clone());
        let mut target = None;
        for record in records.iter().filter(|record| record.owner == canonical) {
            if let RecordData::Alias(name) = &record.data {
                if target.is_some_and(|previous| previous != name) {
                    return Err(DnsError::ConflictingAlias);
                }
                target = Some(name);
                ttl = Some(ttl.map_or(record.ttl, |old| old.min(record.ttl)));
            }
        }
        if let Some(target) = target {
            if records.iter().any(|record| {
                record.owner == canonical
                    && match &record.data {
                        RecordData::Alias(_) => false,
                        // DNSSEC companion records may coexist with CNAMEs.
                        RecordData::Other(24 | 25 | 30 | 46 | 47) => false,
                        _ => true,
                    }
            }) {
                return Err(DnsError::ConflictingAlias);
            }
            if visited.len() > DNS_MAX_ALIAS_DEPTH {
                return Err(DnsError::AliasDepth);
            }
            canonical = target.clone();
            continue;
        }
        break;
    }
    let mut values = Vec::new();
    for record in records.iter().filter(|record| record.owner == canonical) {
        if let RecordData::Value(record_kind, value) = &record.data {
            if *record_kind == kind {
                ttl = Some(ttl.map_or(record.ttl, |old| old.min(record.ttl)));
                if !values.contains(value) {
                    values.push(value.clone());
                }
            }
        }
    }
    Ok(DnsRecordSet {
        question,
        kind,
        canonical_name: canonical,
        values,
        ttl_seconds: ttl.unwrap_or(0),
    })
}

fn decode_record_name(
    packet: &[u8],
    start: usize,
    limit: usize,
) -> Result<(DnsRecordName, usize), DnsError> {
    let mut wire = Vec::new();
    let mut offset = start;
    let mut next = None;
    let mut pointer_ceiling = start;
    loop {
        let boundary = if next.is_none() { limit } else { packet.len() };
        if offset >= boundary {
            return Err(DnsError::Truncated);
        }
        let length = *packet.get(offset).ok_or(DnsError::Truncated)?;
        if length & 0xc0 == 0xc0 {
            if offset + 2 > boundary {
                return Err(DnsError::Truncated);
            }
            let low = *packet.get(offset + 1).ok_or(DnsError::Truncated)?;
            let target = (usize::from(length & 63) << 8) | usize::from(low);
            if target >= packet.len() {
                return Err(DnsError::PointerOutOfBounds);
            }
            if target == offset {
                return Err(DnsError::PointerLoop);
            }
            if target < DNS_HEADER_LEN || target > offset {
                return Err(DnsError::InvalidPointer);
            }
            // Each suffix must precede the name containing its pointer. A
            // strictly decreasing ceiling also catches cycles through labels,
            // without imposing a limit on valid pointer-chain depth.
            if target >= pointer_ceiling {
                return Err(DnsError::PointerLoop);
            }
            pointer_ceiling = target;
            next.get_or_insert(offset + 2);
            offset = target;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(DnsError::InvalidHeader);
        }
        let end = offset + 1 + usize::from(length);
        if end > boundary {
            return Err(DnsError::Truncated);
        }
        let label = packet.get(offset + 1..end).ok_or(DnsError::Truncated)?;
        if wire.len() + 1 + label.len() > MAX_NAME_WIRE_LEN {
            return Err(DnsError::NameTooLong);
        }
        wire.push(length);
        wire.extend(label.iter().map(u8::to_ascii_lowercase));
        offset = end;
        if length == 0 {
            return Ok((DnsRecordName(wire), next.unwrap_or(offset)));
        }
    }
}

fn normalize_ttl(ttl: u32) -> u32 {
    if ttl & 0x8000_0000 != 0 { 0 } else { ttl }
}

struct CacheEntry {
    records: DnsRecordSet,
    expires_at: u64,
}

/// Bounded positive cache. A complete result replaces its previous RRset;
/// members never expire independently or merge with an older response.
pub struct DnsCache {
    entries: VecDeque<CacheEntry>,
    capacity: usize,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            capacity,
        }
    }

    pub fn lookup_records(
        &mut self,
        name: &DnsRecordName,
        kind: DnsRecordType,
        now: u64,
    ) -> Option<DnsRecordSet> {
        self.entries.retain(|entry| entry.expires_at > now);
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.records.question == *name && entry.records.kind == kind)?;
        let mut records = entry.records.clone();
        records.ttl_seconds = ((entry.expires_at - now) / 1000).min(u64::from(u32::MAX)) as u32;
        Some(records)
    }

    pub fn insert_records(&mut self, records: &DnsRecordSet, now: u64) -> Result<(), DnsError> {
        self.entries.retain(|entry| {
            entry.expires_at > now
                && (entry.records.question != records.question
                    || entry.records.kind != records.kind)
        });
        let expires_at = now.saturating_add(u64::from(records.ttl_seconds) * 1000);
        if records.ttl_seconds == 0 || records.values.is_empty() || expires_at <= now {
            return Ok(());
        }
        if self.capacity == 0 {
            return Err(DnsError::CacheCapacity);
        }
        while self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(CacheEntry {
            records: records.clone(),
            expires_at,
        });
        Ok(())
    }

    pub fn lookup(&mut self, name: &DnsName, now: u64) -> Option<[u8; 4]> {
        let records = self.lookup_records(&DnsRecordName::from(name), DnsRecordType::A, now)?;
        match records.values.first()? {
            DnsRecordValue::Ipv4(address) => Some(*address),
            _ => None,
        }
    }

    pub fn insert(
        &mut self,
        name: &DnsName,
        address: [u8; 4],
        ttl_seconds: u32,
        now: u64,
    ) -> Result<(), DnsError> {
        self.insert_records(&DnsRecordSet::ipv4(name, address, ttl_seconds), now)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
