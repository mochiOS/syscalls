use super::{
    MAX_HOSTNAME_LEN, MAX_TCP_IO_LEN, Opcode, WireError, expect_opcode, read_i32, read_u16,
    read_u32, read_u64, write_header, write_i32, write_u16, write_u32, write_u64,
};

pub const TLS_CONNECT_BASE_LEN: usize = 40;
pub const TLS_CONNECT_RESULT_BASE_LEN: usize = 80;
pub const TLS_IO_REQUEST_BASE_LEN: usize = 40;
pub const TLS_IO_RESULT_LEN: usize = 48;
pub const TLS_RECEIVE_REQUEST_LEN: usize = 40;
pub const TLS_RECEIVE_RESULT_BASE_LEN: usize = 48;
pub const TLS_CLOSE_REQUEST_LEN: usize = 40;
pub type TlsReceiveResult<'a> = (u64, i32, TlsFailure, u64, bool, &'a [u8]);
pub const MAX_CERTIFICATE_NAME_LEN: usize = 512;

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsFailure {
    None = 0,
    InvalidServerName = 1,
    InvalidConfiguration = 2,
    RandomUnavailable = 3,
    TimeUnavailable = 4,
    CertificateInvalid = 5,
    HostnameMismatch = 6,
    CertificateChainTooDeep = 7,
    CertificateTooLarge = 8,
    CertificateChainTooLarge = 9,
    AuthenticationFailed = 10,
    BufferLimit = 11,
    Protocol = 12,
    PeerAlert = 13,
    InvalidState = 14,
    Timeout = 15,
    ConnectionLimit = 16,
    Transport = 17,
    PermissionDenied = 18,
}

impl TlsFailure {
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    pub const fn from_wire(value: u16) -> Option<Self> {
        Some(match value {
            0 => Self::None,
            1 => Self::InvalidServerName,
            2 => Self::InvalidConfiguration,
            3 => Self::RandomUnavailable,
            4 => Self::TimeUnavailable,
            5 => Self::CertificateInvalid,
            6 => Self::HostnameMismatch,
            7 => Self::CertificateChainTooDeep,
            8 => Self::CertificateTooLarge,
            9 => Self::CertificateChainTooLarge,
            10 => Self::AuthenticationFailed,
            11 => Self::BufferLimit,
            12 => Self::Protocol,
            13 => Self::PeerAlert,
            14 => Self::InvalidState,
            15 => Self::Timeout,
            16 => Self::ConnectionLimit,
            17 => Self::Transport,
            18 => Self::PermissionDenied,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsConnectResult<'a> {
    pub request_id: u64,
    pub status: i32,
    pub failure: TlsFailure,
    pub handle: u64,
    pub address: [u8; 4],
    pub port: u16,
    pub protocol_version: u16,
    pub cipher_suite: u16,
    pub hostname: &'a str,
    pub certificate_subject: &'a str,
    pub certificate_issuer: &'a str,
    pub certificate_not_before: u64,
    pub certificate_not_after: u64,
}

pub fn encode_tls_connect(
    request_id: u64,
    hostname: &str,
    port: u16,
    timeout_ms: u32,
    out: &mut [u8],
) -> Result<usize, WireError> {
    validate_hostname(hostname)?;
    let length = TLS_CONNECT_BASE_LEN
        .checked_add(hostname.len())
        .ok_or(WireError::HostnameTooLarge(hostname.len()))?;
    write_header(Opcode::TlsConnect, request_id, length, out)?;
    write_u32(out, 24, timeout_ms);
    write_u16(out, 28, port);
    write_u16(out, 30, 0);
    write_u16(out, 32, hostname.len() as u16);
    write_u16(out, 34, 0);
    write_u32(out, 36, 0);
    out[TLS_CONNECT_BASE_LEN..length].copy_from_slice(hostname.as_bytes());
    Ok(length)
}

pub fn decode_tls_connect(bytes: &[u8]) -> Result<(u64, u32, u16, &str), WireError> {
    let header = super::Header::decode(bytes)?;
    expect_opcode(header.opcode, Opcode::TlsConnect)?;
    if bytes.len() < TLS_CONNECT_BASE_LEN {
        return invalid_length(TLS_CONNECT_BASE_LEN, bytes.len());
    }
    let flags = read_u16(bytes, 30);
    let reserved16 = read_u16(bytes, 34);
    let reserved32 = read_u32(bytes, 36);
    if flags != 0 || reserved16 != 0 || reserved32 != 0 {
        return Err(WireError::NonZeroReserved(
            u32::from(flags) | u32::from(reserved16) | reserved32,
        ));
    }
    let hostname_len = usize::from(read_u16(bytes, 32));
    if bytes.len() != TLS_CONNECT_BASE_LEN.saturating_add(hostname_len) {
        return invalid_length(
            TLS_CONNECT_BASE_LEN.saturating_add(hostname_len),
            bytes.len(),
        );
    }
    let hostname =
        core::str::from_utf8(&bytes[TLS_CONNECT_BASE_LEN..]).map_err(|_| WireError::InvalidText)?;
    validate_hostname(hostname)?;
    Ok((
        header.request_id,
        read_u32(bytes, 24),
        read_u16(bytes, 28),
        hostname,
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn encode_tls_connect_result(
    request_id: u64,
    status: i32,
    failure: TlsFailure,
    handle: u64,
    address: [u8; 4],
    port: u16,
    protocol_version: u16,
    cipher_suite: u16,
    hostname: &str,
    certificate_subject: &str,
    certificate_issuer: &str,
    certificate_not_before: u64,
    certificate_not_after: u64,
    out: &mut [u8],
) -> Result<usize, WireError> {
    if !hostname.is_empty() {
        validate_hostname(hostname)?;
    }
    validate_certificate_name(certificate_subject)?;
    validate_certificate_name(certificate_issuer)?;
    let strings_len = hostname
        .len()
        .checked_add(certificate_subject.len())
        .and_then(|length| length.checked_add(certificate_issuer.len()))
        .ok_or(WireError::DataTooLarge(usize::MAX))?;
    let length = TLS_CONNECT_RESULT_BASE_LEN
        .checked_add(strings_len)
        .ok_or(WireError::DataTooLarge(strings_len))?;
    write_header(Opcode::TlsConnectResult, request_id, length, out)?;
    write_i32(out, 24, status);
    write_u16(out, 28, failure.wire_value());
    write_u16(out, 30, 0);
    write_u64(out, 32, handle);
    out[40..44].copy_from_slice(&address);
    write_u16(out, 44, port);
    write_u16(out, 46, protocol_version);
    write_u16(out, 48, cipher_suite);
    write_u16(out, 50, hostname.len() as u16);
    write_u16(out, 52, certificate_subject.len() as u16);
    write_u16(out, 54, certificate_issuer.len() as u16);
    write_u64(out, 56, 0);
    write_u64(out, 64, certificate_not_before);
    write_u64(out, 72, certificate_not_after);
    let mut offset = TLS_CONNECT_RESULT_BASE_LEN;
    for value in [hostname, certificate_subject, certificate_issuer] {
        let end = offset + value.len();
        out[offset..end].copy_from_slice(value.as_bytes());
        offset = end;
    }
    Ok(length)
}

pub fn decode_tls_connect_result(bytes: &[u8]) -> Result<TlsConnectResult<'_>, WireError> {
    let header = super::Header::decode(bytes)?;
    expect_opcode(header.opcode, Opcode::TlsConnectResult)?;
    if bytes.len() < TLS_CONNECT_RESULT_BASE_LEN {
        return invalid_length(TLS_CONNECT_RESULT_BASE_LEN, bytes.len());
    }
    if read_u16(bytes, 30) != 0 || read_u64(bytes, 56) != 0 {
        return Err(WireError::NonZeroReserved(
            u32::from(read_u16(bytes, 30)) | (read_u64(bytes, 56) != 0) as u32,
        ));
    }
    let failure_raw = read_u16(bytes, 28);
    let failure =
        TlsFailure::from_wire(failure_raw).ok_or(WireError::UnknownTlsFailure(failure_raw))?;
    let hostname_len = usize::from(read_u16(bytes, 50));
    let subject_len = usize::from(read_u16(bytes, 52));
    let issuer_len = usize::from(read_u16(bytes, 54));
    if hostname_len > MAX_HOSTNAME_LEN
        || subject_len > MAX_CERTIFICATE_NAME_LEN
        || issuer_len > MAX_CERTIFICATE_NAME_LEN
    {
        return Err(WireError::DataTooLarge(
            hostname_len.max(subject_len).max(issuer_len),
        ));
    }
    let strings_len = hostname_len
        .checked_add(subject_len)
        .and_then(|length| length.checked_add(issuer_len))
        .ok_or(WireError::DataTooLarge(usize::MAX))?;
    let expected = TLS_CONNECT_RESULT_BASE_LEN
        .checked_add(strings_len)
        .ok_or(WireError::DataTooLarge(strings_len))?;
    if bytes.len() != expected {
        return invalid_length(expected, bytes.len());
    }
    let hostname_start = TLS_CONNECT_RESULT_BASE_LEN;
    let subject_start = hostname_start + hostname_len;
    let issuer_start = subject_start + subject_len;
    let hostname = decode_text(&bytes[hostname_start..subject_start])?;
    let certificate_subject = decode_text(&bytes[subject_start..issuer_start])?;
    let certificate_issuer = decode_text(&bytes[issuer_start..])?;
    if !hostname.is_empty() {
        validate_hostname(hostname)?;
    }
    validate_certificate_name(certificate_subject)?;
    validate_certificate_name(certificate_issuer)?;
    Ok(TlsConnectResult {
        request_id: header.request_id,
        status: read_i32(bytes, 24),
        failure,
        handle: read_u64(bytes, 32),
        address: [bytes[40], bytes[41], bytes[42], bytes[43]],
        port: read_u16(bytes, 44),
        protocol_version: read_u16(bytes, 46),
        cipher_suite: read_u16(bytes, 48),
        hostname,
        certificate_subject,
        certificate_issuer,
        certificate_not_before: read_u64(bytes, 64),
        certificate_not_after: read_u64(bytes, 72),
    })
}

pub fn encode_tls_send(
    request_id: u64,
    handle: u64,
    timeout_ms: u32,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, WireError> {
    if data.len() > MAX_TCP_IO_LEN {
        return Err(WireError::DataTooLarge(data.len()));
    }
    let length = TLS_IO_REQUEST_BASE_LEN
        .checked_add(data.len())
        .ok_or(WireError::DataTooLarge(data.len()))?;
    write_header(Opcode::TlsSend, request_id, length, out)?;
    write_u64(out, 24, handle);
    write_u32(out, 32, timeout_ms);
    write_u32(out, 36, data.len() as u32);
    out[TLS_IO_REQUEST_BASE_LEN..length].copy_from_slice(data);
    Ok(length)
}

pub fn decode_tls_send(bytes: &[u8]) -> Result<(u64, u64, u32, &[u8]), WireError> {
    decode_tls_data_request(Opcode::TlsSend, bytes)
}

pub fn encode_tls_receive(
    request_id: u64,
    handle: u64,
    timeout_ms: u32,
    maximum_length: u32,
    out: &mut [u8],
) -> Result<usize, WireError> {
    if maximum_length as usize > MAX_TCP_IO_LEN {
        return Err(WireError::DataTooLarge(maximum_length as usize));
    }
    write_header(Opcode::TlsReceive, request_id, TLS_RECEIVE_REQUEST_LEN, out)?;
    write_u64(out, 24, handle);
    write_u32(out, 32, timeout_ms);
    write_u32(out, 36, maximum_length);
    Ok(TLS_RECEIVE_REQUEST_LEN)
}

pub fn decode_tls_receive(bytes: &[u8]) -> Result<(u64, u64, u32, u32), WireError> {
    let header = super::Header::decode(bytes)?;
    expect_opcode(header.opcode, Opcode::TlsReceive)?;
    if bytes.len() != TLS_RECEIVE_REQUEST_LEN {
        return invalid_length(TLS_RECEIVE_REQUEST_LEN, bytes.len());
    }
    let maximum = read_u32(bytes, 36);
    if maximum as usize > MAX_TCP_IO_LEN {
        return Err(WireError::DataTooLarge(maximum as usize));
    }
    Ok((
        header.request_id,
        read_u64(bytes, 24),
        read_u32(bytes, 32),
        maximum,
    ))
}

pub fn encode_tls_close(
    request_id: u64,
    handle: u64,
    timeout_ms: u32,
    out: &mut [u8],
) -> Result<usize, WireError> {
    write_header(Opcode::TlsClose, request_id, TLS_CLOSE_REQUEST_LEN, out)?;
    write_u64(out, 24, handle);
    write_u32(out, 32, timeout_ms);
    write_u32(out, 36, 0);
    Ok(TLS_CLOSE_REQUEST_LEN)
}

pub fn decode_tls_close(bytes: &[u8]) -> Result<(u64, u64, u32), WireError> {
    let header = super::Header::decode(bytes)?;
    expect_opcode(header.opcode, Opcode::TlsClose)?;
    if bytes.len() != TLS_CLOSE_REQUEST_LEN {
        return invalid_length(TLS_CLOSE_REQUEST_LEN, bytes.len());
    }
    let reserved = read_u32(bytes, 36);
    if reserved != 0 {
        return Err(WireError::NonZeroReserved(reserved));
    }
    Ok((header.request_id, read_u64(bytes, 24), read_u32(bytes, 32)))
}

pub fn encode_tls_io_result(
    opcode: Opcode,
    request_id: u64,
    status: i32,
    failure: TlsFailure,
    handle: u64,
    transferred: u32,
    out: &mut [u8],
) -> Result<usize, WireError> {
    if !matches!(opcode, Opcode::TlsSendResult | Opcode::TlsCloseResult) {
        return Err(WireError::UnexpectedOpcode {
            expected: Opcode::TlsSendResult,
            actual: opcode,
        });
    }
    write_header(opcode, request_id, TLS_IO_RESULT_LEN, out)?;
    write_i32(out, 24, status);
    write_u16(out, 28, failure.wire_value());
    write_u16(out, 30, 0);
    write_u32(out, 32, transferred);
    write_u32(out, 36, 0);
    write_u64(out, 40, handle);
    Ok(TLS_IO_RESULT_LEN)
}

pub fn decode_tls_io_result(
    expected: Opcode,
    bytes: &[u8],
) -> Result<(u64, i32, TlsFailure, u64, u32), WireError> {
    let header = super::Header::decode(bytes)?;
    expect_opcode(header.opcode, expected)?;
    if bytes.len() != TLS_IO_RESULT_LEN {
        return invalid_length(TLS_IO_RESULT_LEN, bytes.len());
    }
    if read_u16(bytes, 30) != 0 || read_u32(bytes, 36) != 0 {
        return Err(WireError::NonZeroReserved(
            u32::from(read_u16(bytes, 30)) | read_u32(bytes, 36),
        ));
    }
    let failure_raw = read_u16(bytes, 28);
    let failure =
        TlsFailure::from_wire(failure_raw).ok_or(WireError::UnknownTlsFailure(failure_raw))?;
    Ok((
        header.request_id,
        read_i32(bytes, 24),
        failure,
        read_u64(bytes, 40),
        read_u32(bytes, 32),
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn encode_tls_receive_result(
    request_id: u64,
    status: i32,
    failure: TlsFailure,
    handle: u64,
    closed: bool,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, WireError> {
    if data.len() > MAX_TCP_IO_LEN {
        return Err(WireError::DataTooLarge(data.len()));
    }
    let length = TLS_RECEIVE_RESULT_BASE_LEN
        .checked_add(data.len())
        .ok_or(WireError::DataTooLarge(data.len()))?;
    write_header(Opcode::TlsReceiveResult, request_id, length, out)?;
    write_i32(out, 24, status);
    write_u16(out, 28, failure.wire_value());
    write_u16(out, 30, u16::from(closed));
    write_u32(out, 32, data.len() as u32);
    write_u32(out, 36, 0);
    write_u64(out, 40, handle);
    out[TLS_RECEIVE_RESULT_BASE_LEN..length].copy_from_slice(data);
    Ok(length)
}

pub fn decode_tls_receive_result(bytes: &[u8]) -> Result<TlsReceiveResult<'_>, WireError> {
    let header = super::Header::decode(bytes)?;
    expect_opcode(header.opcode, Opcode::TlsReceiveResult)?;
    if bytes.len() < TLS_RECEIVE_RESULT_BASE_LEN {
        return invalid_length(TLS_RECEIVE_RESULT_BASE_LEN, bytes.len());
    }
    let flags = read_u16(bytes, 30);
    if flags > 1 || read_u32(bytes, 36) != 0 {
        return Err(WireError::NonZeroReserved(
            u32::from(flags) | read_u32(bytes, 36),
        ));
    }
    let data_len = read_u32(bytes, 32) as usize;
    if data_len > MAX_TCP_IO_LEN
        || bytes.len() != TLS_RECEIVE_RESULT_BASE_LEN.saturating_add(data_len)
    {
        return invalid_length(
            TLS_RECEIVE_RESULT_BASE_LEN.saturating_add(data_len),
            bytes.len(),
        );
    }
    let failure_raw = read_u16(bytes, 28);
    let failure =
        TlsFailure::from_wire(failure_raw).ok_or(WireError::UnknownTlsFailure(failure_raw))?;
    Ok((
        header.request_id,
        read_i32(bytes, 24),
        failure,
        read_u64(bytes, 40),
        flags == 1,
        &bytes[TLS_RECEIVE_RESULT_BASE_LEN..],
    ))
}

fn decode_tls_data_request(
    expected: Opcode,
    bytes: &[u8],
) -> Result<(u64, u64, u32, &[u8]), WireError> {
    let header = super::Header::decode(bytes)?;
    expect_opcode(header.opcode, expected)?;
    if bytes.len() < TLS_IO_REQUEST_BASE_LEN {
        return invalid_length(TLS_IO_REQUEST_BASE_LEN, bytes.len());
    }
    let data_len = read_u32(bytes, 36) as usize;
    if data_len > MAX_TCP_IO_LEN {
        return Err(WireError::DataTooLarge(data_len));
    }
    if bytes.len() != TLS_IO_REQUEST_BASE_LEN.saturating_add(data_len) {
        return invalid_length(
            TLS_IO_REQUEST_BASE_LEN.saturating_add(data_len),
            bytes.len(),
        );
    }
    Ok((
        header.request_id,
        read_u64(bytes, 24),
        read_u32(bytes, 32),
        &bytes[TLS_IO_REQUEST_BASE_LEN..],
    ))
}

fn validate_hostname(hostname: &str) -> Result<(), WireError> {
    if hostname.is_empty() || hostname.len() > MAX_HOSTNAME_LEN {
        return Err(WireError::HostnameTooLarge(hostname.len()));
    }
    if hostname
        .as_bytes()
        .iter()
        .any(|byte| *byte == 0 || !byte.is_ascii())
    {
        return Err(WireError::InvalidText);
    }
    Ok(())
}

fn validate_certificate_name(value: &str) -> Result<(), WireError> {
    if value.len() > MAX_CERTIFICATE_NAME_LEN {
        return Err(WireError::DataTooLarge(value.len()));
    }
    if value
        .as_bytes()
        .iter()
        .any(|byte| *byte == 0 || byte.is_ascii_control())
    {
        return Err(WireError::InvalidText);
    }
    Ok(())
}

fn decode_text(bytes: &[u8]) -> Result<&str, WireError> {
    core::str::from_utf8(bytes).map_err(|_| WireError::InvalidText)
}

fn invalid_length<T>(declared: usize, actual: usize) -> Result<T, WireError> {
    Err(WireError::InvalidLength { declared, actual })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_connect_is_golden_unaligned_and_exact_length() {
        let mut storage = [0u8; TLS_CONNECT_BASE_LEN + 10];
        let length =
            encode_tls_connect(u64::MAX, "localhost", 443, 5_000, &mut storage[1..]).unwrap();
        assert_eq!(length, TLS_CONNECT_BASE_LEN + 9);
        assert_eq!(
            &storage[1..25],
            &[
                0x4d, 0x4e, 0x45, 0x54, 1, 0, 0x20, 1, 49, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff,
            ]
        );
        assert_eq!(
            decode_tls_connect(&storage[1..1 + length]),
            Ok((u64::MAX, 5_000, 443, "localhost"))
        );
        assert!(matches!(
            decode_tls_connect(&storage[1..length]),
            Err(WireError::InvalidLength { .. })
        ));
    }

    #[test]
    fn tls_connect_result_round_trip_and_reserved_validation() {
        let mut bytes = [0u8; 1536];
        let length = encode_tls_connect_result(
            7,
            0,
            TlsFailure::None,
            u64::MAX,
            [10, 0, 2, 2],
            443,
            0x0304,
            0x1303,
            "localhost",
            "CN=localhost",
            "CN=Test Root",
            1,
            u64::MAX,
            &mut bytes,
        )
        .unwrap();
        assert_eq!(
            decode_tls_connect_result(&bytes[..length]),
            Ok(TlsConnectResult {
                request_id: 7,
                status: 0,
                failure: TlsFailure::None,
                handle: u64::MAX,
                address: [10, 0, 2, 2],
                port: 443,
                protocol_version: 0x0304,
                cipher_suite: 0x1303,
                hostname: "localhost",
                certificate_subject: "CN=localhost",
                certificate_issuer: "CN=Test Root",
                certificate_not_before: 1,
                certificate_not_after: u64::MAX,
            })
        );
        bytes[56] = 1;
        assert!(matches!(
            decode_tls_connect_result(&bytes[..length]),
            Err(WireError::NonZeroReserved(_))
        ));
    }

    #[test]
    fn tls_io_messages_round_trip_and_enforce_bounds() {
        let mut bytes = [0u8; 4200];
        let length = encode_tls_send(1, 2, 3, b"hello", &mut bytes).unwrap();
        assert_eq!(
            decode_tls_send(&bytes[..length]),
            Ok((1, 2, 3, b"hello".as_slice()))
        );
        encode_tls_receive(4, 5, 6, 4096, &mut bytes).unwrap();
        assert_eq!(
            decode_tls_receive(&bytes[..TLS_RECEIVE_REQUEST_LEN]),
            Ok((4, 5, 6, 4096))
        );
        encode_tls_close(7, 8, 9, &mut bytes).unwrap();
        assert_eq!(
            decode_tls_close(&bytes[..TLS_CLOSE_REQUEST_LEN]),
            Ok((7, 8, 9))
        );
        assert!(matches!(
            encode_tls_send(1, 2, 3, &[0; MAX_TCP_IO_LEN + 1], &mut bytes),
            Err(WireError::DataTooLarge(_))
        ));
    }

    #[test]
    fn tls_results_round_trip_and_reject_unknown_failure() {
        let mut bytes = [0u8; 128];
        encode_tls_io_result(
            Opcode::TlsSendResult,
            1,
            -5,
            TlsFailure::Transport,
            9,
            4,
            &mut bytes,
        )
        .unwrap();
        assert_eq!(
            decode_tls_io_result(Opcode::TlsSendResult, &bytes[..TLS_IO_RESULT_LEN]),
            Ok((1, -5, TlsFailure::Transport, 9, 4))
        );
        let length =
            encode_tls_receive_result(2, 0, TlsFailure::None, 9, true, b"done", &mut bytes)
                .unwrap();
        assert_eq!(
            decode_tls_receive_result(&bytes[..length]),
            Ok((2, 0, TlsFailure::None, 9, true, b"done".as_slice()))
        );
        bytes[28..30].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(matches!(
            decode_tls_receive_result(&bytes[..length]),
            Err(WireError::UnknownTlsFailure(u16::MAX))
        ));
    }

    #[test]
    fn tls_encoders_reject_short_output_buffers() {
        assert!(matches!(
            encode_tls_connect(1, "localhost", 443, 1, &mut [0u8; 8]),
            Err(WireError::BufferTooSmall { .. })
        ));
        assert!(matches!(
            encode_tls_receive_result(1, 0, TlsFailure::None, 1, false, b"x", &mut [0u8; 8]),
            Err(WireError::BufferTooSmall { .. })
        ));
    }
}
