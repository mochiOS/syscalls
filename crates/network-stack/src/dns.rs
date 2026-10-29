use alloc::string::String;

#[path = "dns/records.rs"]
mod records;
pub use records::*;

pub const DNS_PORT: u16 = 53;
pub const DNS_MAX_MESSAGE_LEN: usize = 512;
pub const DNS_MAX_NAME_LEN: usize = 253;
pub const DNS_MAX_LABEL_LEN: usize = 63;
const DNS_HEADER_LEN: usize = 12;

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
    UnsupportedExtendedResponseCode(u16),
    UnsupportedRecord,
    InvalidRecordLength,
    PointerOutOfBounds,
    PointerLoop,
    InvalidPointer,
    TruncatedResponse,
    AliasLoop,
    AliasDepth,
    ConflictingAlias,
    NoData,
    CacheCapacity,
    Timeout,
    RetryLimit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsName(String);

impl DnsName {
    pub fn parse(input: &str) -> Result<Self, DnsError> {
        let input = input.strip_suffix('.').unwrap_or(input);
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
    encode_dns_record_query(
        transaction_id,
        &DnsRecordName::from(name),
        DnsRecordType::A,
        out,
    )
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
    let records = decode_dns_records(
        packet,
        transaction_id,
        &DnsRecordName::from(expected_name),
        DnsRecordType::A,
    )?;
    match records.values().first() {
        Some(DnsRecordValue::Ipv4(address)) => Ok(DnsAnswer {
            address: *address,
            ttl_seconds: records.ttl_seconds(),
        }),
        _ => Err(DnsError::UnsupportedRecord),
    }
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

fn read_u16(packet: &[u8], offset: usize) -> Result<u16, DnsError> {
    let bytes = packet.get(offset..offset + 2).ok_or(DnsError::Truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(packet: &[u8], offset: usize) -> Result<u32, DnsError> {
    let bytes = packet.get(offset..offset + 4).ok_or(DnsError::Truncated)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
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
            (1u8, DnsResponseCode::FormatError),
            (2, DnsResponseCode::ServerFailure),
            (3, DnsResponseCode::NameError),
            (4, DnsResponseCode::NotImplemented),
            (5, DnsResponseCode::Refused),
        ] {
            let mut packet = [0; DNS_MAX_MESSAGE_LEN];
            let length = encode_dns_query(1, &name, &mut packet).unwrap();
            packet[2..4].copy_from_slice(&(0x8180u16 | u16::from(code)).to_be_bytes());
            assert_eq!(
                decode_dns_response(&packet[..length], 1, &name),
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
