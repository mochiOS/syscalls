use alloc::collections::VecDeque;
use alloc::string::{String, ToString};

pub const DNS_PORT: u16 = 53;
pub const DNS_MAX_MESSAGE_LEN: usize = 512;
pub const DNS_MAX_NAME_LEN: usize = 253;
pub const DNS_MAX_LABEL_LEN: usize = 63;
const DNS_HEADER_LEN: usize = 12;
const DNS_MAX_POINTERS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsError {
    EmptyName,
    NameTooLong,
    LabelTooLong,
    EmptyLabel,
    InvalidCharacter,
    InvalidHyphen,
    BufferTooSmall,
    MessageTooLarge,
    Truncated,
    InvalidHeader,
    TransactionMismatch,
    QuestionMismatch,
    Response(DnsResponseCode),
    UnsupportedResponseCode(u8),
    UnsupportedRecord,
    InvalidRecordLength,
    PointerOutOfBounds,
    PointerLoop,
    CacheCapacity,
    Timeout,
    RetryLimit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsName(String);

impl DnsName {
    pub fn parse(input: &str) -> Result<Self, DnsError> {
        if input.is_empty() {
            return Err(DnsError::EmptyName);
        }
        if input.len() > DNS_MAX_NAME_LEN {
            return Err(DnsError::NameTooLong);
        }
        if !input.is_ascii() {
            return Err(DnsError::InvalidCharacter);
        }
        let mut normalized = String::with_capacity(input.len());
        for (index, label) in input.split('.').enumerate() {
            if label.is_empty() {
                return Err(DnsError::EmptyLabel);
            }
            if label.len() > DNS_MAX_LABEL_LEN {
                return Err(DnsError::LabelTooLong);
            }
            let bytes = label.as_bytes();
            if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
                return Err(DnsError::InvalidHyphen);
            }
            if bytes
                .iter()
                .any(|byte| !byte.is_ascii_alphanumeric() && *byte != b'-')
            {
                return Err(DnsError::InvalidCharacter);
            }
            if index != 0 {
                normalized.push('.');
            }
            for byte in bytes {
                normalized.push(char::from(byte.to_ascii_lowercase()));
            }
        }
        Ok(Self(normalized))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn encode(&self, out: &mut [u8]) -> Result<usize, DnsError> {
        let required = self.0.len().checked_add(2).ok_or(DnsError::NameTooLong)?;
        if out.len() < required {
            return Err(DnsError::BufferTooSmall);
        }
        let mut offset = 0;
        for label in self.0.split('.') {
            out[offset] = u8::try_from(label.len()).map_err(|_| DnsError::LabelTooLong)?;
            offset += 1;
            out[offset..offset + label.len()].copy_from_slice(label.as_bytes());
            offset += label.len();
        }
        out[offset] = 0;
        Ok(offset + 1)
    }
}

pub fn parse_ipv4_literal(input: &str) -> Option<[u8; 4]> {
    let mut address = [0u8; 4];
    let mut count = 0usize;
    for part in input.split('.') {
        if count >= address.len()
            || part.is_empty()
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let mut value = 0u16;
        for byte in part.bytes() {
            value = value.checked_mul(10)?.checked_add(u16::from(byte - b'0'))?;
            if value > 255 {
                return None;
            }
        }
        address[count] = value as u8;
        count += 1;
    }
    (count == address.len()).then_some(address)
}

pub fn encode_dns_query(
    transaction_id: u16,
    name: &DnsName,
    out: &mut [u8],
) -> Result<usize, DnsError> {
    if out.len() < DNS_HEADER_LEN {
        return Err(DnsError::BufferTooSmall);
    }
    out[..DNS_HEADER_LEN].fill(0);
    out[0..2].copy_from_slice(&transaction_id.to_be_bytes());
    out[2..4].copy_from_slice(&0x0100u16.to_be_bytes());
    out[4..6].copy_from_slice(&1u16.to_be_bytes());
    let name_length = name.encode(&mut out[DNS_HEADER_LEN..])?;
    let length = DNS_HEADER_LEN
        .checked_add(name_length)
        .and_then(|value| value.checked_add(4))
        .ok_or(DnsError::MessageTooLarge)?;
    if length > DNS_MAX_MESSAGE_LEN {
        return Err(DnsError::MessageTooLarge);
    }
    if out.len() < length {
        return Err(DnsError::BufferTooSmall);
    }
    let question = DNS_HEADER_LEN + name_length;
    out[question..question + 2].copy_from_slice(&1u16.to_be_bytes());
    out[question + 2..question + 4].copy_from_slice(&1u16.to_be_bytes());
    Ok(length)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsAnswer {
    pub address: [u8; 4],
    pub ttl_seconds: u32,
}

pub fn decode_dns_response(
    packet: &[u8],
    transaction_id: u16,
    expected_name: &DnsName,
) -> Result<DnsAnswer, DnsError> {
    if packet.len() > DNS_MAX_MESSAGE_LEN {
        return Err(DnsError::MessageTooLarge);
    }
    if packet.len() < DNS_HEADER_LEN {
        return Err(DnsError::Truncated);
    }
    if read_u16(packet, 0)? != transaction_id {
        return Err(DnsError::TransactionMismatch);
    }
    let flags = read_u16(packet, 2)?;
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 || flags & 0x0200 != 0 {
        return Err(DnsError::InvalidHeader);
    }
    let response_code = decode_response_code((flags & 0x000f) as u8)?;
    if response_code != DnsResponseCode::NoError {
        return Err(DnsError::Response(response_code));
    }
    if read_u16(packet, 4)? != 1 {
        return Err(DnsError::QuestionMismatch);
    }
    let answer_count = read_u16(packet, 6)?;
    if answer_count == 0 {
        return Err(DnsError::UnsupportedRecord);
    }
    let authority_count = read_u16(packet, 8)?;
    let additional_count = read_u16(packet, 10)?;
    let (question_name, mut offset) = decode_name(packet, DNS_HEADER_LEN)?;
    if question_name != expected_name.as_str() {
        return Err(DnsError::QuestionMismatch);
    }
    let question_type = read_u16(packet, offset)?;
    let question_class = read_u16(packet, offset + 2)?;
    offset = offset.checked_add(4).ok_or(DnsError::Truncated)?;
    if question_type != 1 || question_class != 1 {
        return Err(DnsError::QuestionMismatch);
    }
    let record_count = usize::from(answer_count)
        .checked_add(usize::from(authority_count))
        .and_then(|count| count.checked_add(usize::from(additional_count)))
        .ok_or(DnsError::MessageTooLarge)?;
    let mut answer = None;
    for index in 0..record_count {
        let (record_name, next) = decode_name(packet, offset)?;
        let record_type = read_u16(packet, next)?;
        let class = read_u16(packet, next + 2)?;
        let ttl = read_u32(packet, next + 4)?;
        let data_length = usize::from(read_u16(packet, next + 8)?);
        let data = next.checked_add(10).ok_or(DnsError::Truncated)?;
        let end = data.checked_add(data_length).ok_or(DnsError::Truncated)?;
        if end > packet.len() {
            return Err(DnsError::Truncated);
        }
        if record_type == 1 && class == 1 {
            if data_length != 4 {
                return Err(DnsError::InvalidRecordLength);
            }
            if index < usize::from(answer_count)
                && record_name == expected_name.as_str()
                && answer.is_none()
            {
                answer = Some(DnsAnswer {
                    address: [
                        packet[data],
                        packet[data + 1],
                        packet[data + 2],
                        packet[data + 3],
                    ],
                    ttl_seconds: ttl,
                });
            }
        }
        offset = end;
    }
    if offset != packet.len() {
        return Err(DnsError::InvalidHeader);
    }
    answer.ok_or(DnsError::UnsupportedRecord)
}

fn decode_response_code(code: u8) -> Result<DnsResponseCode, DnsError> {
    Ok(match code {
        0 => DnsResponseCode::NoError,
        1 => DnsResponseCode::FormatError,
        2 => DnsResponseCode::ServerFailure,
        3 => DnsResponseCode::NameError,
        4 => DnsResponseCode::NotImplemented,
        5 => DnsResponseCode::Refused,
        other => return Err(DnsError::UnsupportedResponseCode(other)),
    })
}

fn decode_name(packet: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut offset = start;
    let mut next_offset = None;
    let mut pointers = [usize::MAX; DNS_MAX_POINTERS];
    let mut pointer_count = 0usize;
    loop {
        let length = *packet.get(offset).ok_or(DnsError::Truncated)?;
        if length & 0xc0 == 0xc0 {
            let low = *packet.get(offset + 1).ok_or(DnsError::Truncated)?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(low);
            if pointer >= packet.len() {
                return Err(DnsError::PointerOutOfBounds);
            }
            if pointer_count >= DNS_MAX_POINTERS || pointers[..pointer_count].contains(&pointer) {
                return Err(DnsError::PointerLoop);
            }
            pointers[pointer_count] = pointer;
            pointer_count += 1;
            if next_offset.is_none() {
                next_offset = Some(offset + 2);
            }
            offset = pointer;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(DnsError::InvalidHeader);
        }
        offset += 1;
        if length == 0 {
            let consumed = next_offset.unwrap_or(offset);
            if name.is_empty() || name.len() > DNS_MAX_NAME_LEN {
                return Err(DnsError::InvalidHeader);
            }
            return Ok((name, consumed));
        }
        let length = usize::from(length);
        if length > DNS_MAX_LABEL_LEN {
            return Err(DnsError::LabelTooLong);
        }
        let end = offset.checked_add(length).ok_or(DnsError::Truncated)?;
        let label = packet.get(offset..end).ok_or(DnsError::Truncated)?;
        if label
            .iter()
            .any(|byte| !byte.is_ascii_alphanumeric() && *byte != b'-')
            || label.first() == Some(&b'-')
            || label.last() == Some(&b'-')
        {
            return Err(DnsError::InvalidCharacter);
        }
        if !name.is_empty() {
            name.push('.');
        }
        if name.len().saturating_add(length) > DNS_MAX_NAME_LEN {
            return Err(DnsError::NameTooLong);
        }
        for byte in label {
            name.push(char::from(byte.to_ascii_lowercase()));
        }
        offset = end;
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, DnsError> {
    let bytes = packet.get(offset..offset + 2).ok_or(DnsError::Truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, DnsError> {
    let bytes = packet.get(offset..offset + 4).ok_or(DnsError::Truncated)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsCacheEntry {
    pub hostname: String,
    pub address: [u8; 4],
    pub expires_at: u64,
}

pub struct DnsCache {
    entries: VecDeque<DnsCacheEntry>,
    capacity: usize,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn lookup(&mut self, name: &DnsName, now: u64) -> Option<[u8; 4]> {
        self.entries.retain(|entry| entry.expires_at > now);
        self.entries
            .iter()
            .find(|entry| entry.hostname == name.as_str())
            .map(|entry| entry.address)
    }

    pub fn insert(
        &mut self,
        name: &DnsName,
        address: [u8; 4],
        ttl_seconds: u32,
        now: u64,
    ) -> Result<(), DnsError> {
        self.entries.retain(|entry| entry.hostname != name.as_str());
        if ttl_seconds == 0 {
            return Ok(());
        }
        if self.capacity == 0 {
            return Err(DnsError::CacheCapacity);
        }
        while self.entries.len() >= self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(DnsCacheEntry {
            hostname: name.as_str().to_string(),
            address,
            expires_at: now.saturating_add(u64::from(ttl_seconds).saturating_mul(1_000)),
        });
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsRetryAction {
    Wait,
    Send,
    Failed(DnsErrorKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsErrorKind {
    Timeout,
    RetryLimit,
}

pub struct DnsRetry {
    deadline: u64,
    next_send: u64,
    base_delay: u64,
    attempts: u8,
    maximum_attempts: u8,
}

impl DnsRetry {
    pub fn new(now: u64, timeout: u64, base_delay: u64, maximum_attempts: u8) -> Self {
        Self {
            deadline: now.saturating_add(timeout),
            next_send: now,
            base_delay,
            attempts: 0,
            maximum_attempts,
        }
    }

    pub fn poll(&mut self, now: u64) -> DnsRetryAction {
        if now >= self.deadline {
            return DnsRetryAction::Failed(DnsErrorKind::Timeout);
        }
        if now < self.next_send {
            return DnsRetryAction::Wait;
        }
        if self.attempts >= self.maximum_attempts {
            return DnsRetryAction::Failed(DnsErrorKind::RetryLimit);
        }
        let shift = u32::from(self.attempts.min(20));
        let delay = self.base_delay.saturating_mul(1u64 << shift);
        self.attempts = self.attempts.saturating_add(1);
        self.next_send = now.saturating_add(delay);
        DnsRetryAction::Send
    }

    pub const fn attempts(&self) -> u8 {
        self.attempts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(name: &DnsName, id: u16, rcode: u8, rdata: &[u8], ttl: u32) -> alloc::vec::Vec<u8> {
        let mut packet = alloc::vec![0u8; DNS_MAX_MESSAGE_LEN];
        let query_len = encode_dns_query(id, name, &mut packet).unwrap();
        packet[2..4].copy_from_slice(&(0x8180u16 | u16::from(rcode)).to_be_bytes());
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        let mut offset = query_len;
        packet[offset..offset + 2].copy_from_slice(&[0xc0, 0x0c]);
        offset += 2;
        packet[offset..offset + 2].copy_from_slice(&1u16.to_be_bytes());
        packet[offset + 2..offset + 4].copy_from_slice(&1u16.to_be_bytes());
        packet[offset + 4..offset + 8].copy_from_slice(&ttl.to_be_bytes());
        packet[offset + 8..offset + 10].copy_from_slice(&(rdata.len() as u16).to_be_bytes());
        offset += 10;
        packet[offset..offset + rdata.len()].copy_from_slice(rdata);
        packet.truncate(offset + rdata.len());
        packet
    }

    #[test]
    fn hostname_validation_and_encoding() {
        let name = DnsName::parse("Example.COM").unwrap();
        assert_eq!(name.as_str(), "example.com");
        let mut encoded = [0u8; 20];
        let length = name.encode(&mut encoded).unwrap();
        assert_eq!(&encoded[..length], b"\x07example\x03com\0");
        assert_eq!(DnsName::parse(""), Err(DnsError::EmptyName));
        assert_eq!(DnsName::parse("a..b"), Err(DnsError::EmptyLabel));
        assert_eq!(DnsName::parse("-bad.test"), Err(DnsError::InvalidHyphen));
        assert_eq!(DnsName::parse("bad_.test"), Err(DnsError::InvalidCharacter));
        let too_long = alloc::format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63)
        );
        assert_eq!(DnsName::parse(&too_long), Err(DnsError::NameTooLong));
        assert_eq!(
            DnsName::parse(&alloc::string::String::from_iter(core::iter::repeat_n(
                'a', 64
            ))),
            Err(DnsError::LabelTooLong)
        );
        assert_eq!(parse_ipv4_literal("10.0.2.2"), Some([10, 0, 2, 2]));
        assert_eq!(parse_ipv4_literal("10.0.2.999"), None);
    }

    #[test]
    fn query_is_standard_recursive_a_in() {
        let name = DnsName::parse("example.com").unwrap();
        let mut packet = [0u8; DNS_MAX_MESSAGE_LEN];
        let length = encode_dns_query(0x1234, &name, &mut packet).unwrap();
        assert_eq!(&packet[..6], &[0x12, 0x34, 0x01, 0x00, 0x00, 0x01]);
        assert_eq!(&packet[length - 4..length], &[0, 1, 0, 1]);
    }

    #[test]
    fn response_and_compression_decode() {
        let name = DnsName::parse("example.com").unwrap();
        let packet = response(&name, 7, 0, &[93, 184, 216, 34], 60);
        assert_eq!(
            decode_dns_response(&packet, 7, &name),
            Ok(DnsAnswer {
                address: [93, 184, 216, 34],
                ttl_seconds: 60
            })
        );
        assert_eq!(
            decode_dns_response(&packet, 8, &name),
            Err(DnsError::TransactionMismatch)
        );
        let bad_length = response(&name, 7, 0, &[1, 2, 3], 60);
        assert_eq!(
            decode_dns_response(&bad_length, 7, &name),
            Err(DnsError::InvalidRecordLength)
        );
    }

    #[test]
    fn response_codes_are_distinct() {
        let name = DnsName::parse("example.com").unwrap();
        for (code, expected) in [
            (1, DnsResponseCode::FormatError),
            (2, DnsResponseCode::ServerFailure),
            (3, DnsResponseCode::NameError),
            (4, DnsResponseCode::NotImplemented),
            (5, DnsResponseCode::Refused),
        ] {
            assert_eq!(
                decode_dns_response(&response(&name, 1, code, &[1, 2, 3, 4], 1), 1, &name),
                Err(DnsError::Response(expected))
            );
        }
    }

    #[test]
    fn compression_pointer_failures_are_rejected() {
        let name = DnsName::parse("example.com").unwrap();
        let mut packet = response(&name, 1, 0, &[1, 2, 3, 4], 1);
        let answer = encode_dns_query(1, &name, &mut [0u8; DNS_MAX_MESSAGE_LEN]).unwrap();
        packet[answer..answer + 2].copy_from_slice(&[0xff, 0xff]);
        assert_eq!(
            decode_dns_response(&packet, 1, &name),
            Err(DnsError::PointerOutOfBounds)
        );
        packet[answer..answer + 2]
            .copy_from_slice(&[0xc0 | (((answer >> 8) & 0x3f) as u8), answer as u8]);
        assert_eq!(
            decode_dns_response(&packet, 1, &name),
            Err(DnsError::PointerLoop)
        );
    }

    #[test]
    fn mixed_labels_and_pointer_decode_without_trusting_packet_offsets() {
        let name = DnsName::parse("foo.example.com").unwrap();
        let mut packet = response(&name, 9, 0, &[10, 0, 2, 2], 5);
        let mut query = [0u8; DNS_MAX_MESSAGE_LEN];
        let answer_offset = encode_dns_query(9, &name, &mut query).unwrap();
        packet.splice(
            answer_offset..answer_offset + 2,
            [3, b'f', b'o', b'o', 0xc0, 0x10],
        );
        assert_eq!(
            decode_dns_response(&packet, 9, &name),
            Ok(DnsAnswer {
                address: [10, 0, 2, 2],
                ttl_seconds: 5,
            })
        );
    }

    #[test]
    fn truncated_and_oversized_responses_never_parse() {
        let name = DnsName::parse("example.com").unwrap();
        let packet = response(&name, 1, 0, &[1, 2, 3, 4], 1);
        for length in 0..packet.len() {
            assert!(decode_dns_response(&packet[..length], 1, &name).is_err());
        }
        let mut oversized = packet;
        oversized.resize(DNS_MAX_MESSAGE_LEN + 1, 0);
        assert_eq!(
            decode_dns_response(&oversized, 1, &name),
            Err(DnsError::MessageTooLarge)
        );

        let mut trailing = response(&name, 1, 0, &[1, 2, 3, 4], 1);
        trailing.push(0);
        assert_eq!(
            decode_dns_response(&trailing, 1, &name),
            Err(DnsError::InvalidHeader)
        );
    }

    #[test]
    fn cache_is_bounded_and_expires() {
        let a = DnsName::parse("a.test").unwrap();
        let b = DnsName::parse("b.test").unwrap();
        let mut cache = DnsCache::new(1);
        assert_eq!(cache.lookup(&a, 0), None);
        cache.insert(&a, [1, 2, 3, 4], 1, 0).unwrap();
        assert_eq!(cache.lookup(&a, 999), Some([1, 2, 3, 4]));
        assert_eq!(cache.lookup(&a, 1_000), None);
        cache.insert(&a, [1; 4], 10, 0).unwrap();
        cache.insert(&b, [2; 4], 10, 0).unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.lookup(&a, 1), None);
        assert_eq!(cache.lookup(&b, 1), Some([2; 4]));
        cache.insert(&b, [3; 4], 0, 1).unwrap();
        assert!(cache.is_empty());
    }

    #[test]
    fn retry_and_timeout_are_bounded() {
        let mut retry = DnsRetry::new(0, 10_000, 100, 2);
        assert_eq!(retry.poll(0), DnsRetryAction::Send);
        assert_eq!(retry.poll(50), DnsRetryAction::Wait);
        assert_eq!(retry.poll(100), DnsRetryAction::Send);
        assert_eq!(
            retry.poll(300),
            DnsRetryAction::Failed(DnsErrorKind::RetryLimit)
        );
        let mut timeout = DnsRetry::new(0, 10, 100, 3);
        assert_eq!(
            timeout.poll(10),
            DnsRetryAction::Failed(DnsErrorKind::Timeout)
        );
    }
}
