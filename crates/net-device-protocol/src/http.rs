use super::{
    Header, Opcode, WireError, expect_opcode, read_i32, read_u16, read_u32, read_u64, write_header,
    write_i32, write_u16, write_u32, write_u64,
};

pub const HTTP_REQUEST_BASE_LEN: usize = 48;
pub const HTTP_REQUEST_RESULT_BASE_LEN: usize = 56;
pub const HTTP_READ_REQUEST_LEN: usize = 40;
pub const HTTP_READ_RESULT_BASE_LEN: usize = 48;
pub const HTTP_CLOSE_REQUEST_LEN: usize = 40;
pub const HTTP_CLOSE_RESULT_LEN: usize = 48;
pub type HttpReadResult<'a> = (u64, i32, HttpFailure, u64, bool, &'a [u8]);
pub const MAX_HTTP_URL_LEN: usize = 2_048;
pub const MAX_HTTP_CONTENT_TYPE_LEN: usize = 256;
pub const MAX_HTTP_IPC_DATA_LEN: usize = 4_096;

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get = 1,
    Post = 2,
}

impl HttpMethod {
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    const fn from_wire(value: u16) -> Option<Self> {
        Some(match value {
            1 => Self::Get,
            2 => Self::Post,
            _ => return None,
        })
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpStream {
    Headers = 1,
    Body = 2,
}

impl HttpStream {
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    const fn from_wire(value: u16) -> Option<Self> {
        Some(match value {
            1 => Self::Headers,
            2 => Self::Body,
            _ => return None,
        })
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpFailure {
    None = 0,
    InvalidUrl = 1,
    InvalidRequest = 2,
    HeaderLimit = 3,
    BodyLimit = 4,
    InvalidResponse = 5,
    ChunkError = 6,
    RedirectRejected = 7,
    Tls = 8,
    Timeout = 9,
    ConnectionLimit = 10,
    InvalidState = 11,
    PermissionDenied = 12,
}

impl HttpFailure {
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    const fn from_wire(value: u16) -> Option<Self> {
        Some(match value {
            0 => Self::None,
            1 => Self::InvalidUrl,
            2 => Self::InvalidRequest,
            3 => Self::HeaderLimit,
            4 => Self::BodyLimit,
            5 => Self::InvalidResponse,
            6 => Self::ChunkError,
            7 => Self::RedirectRejected,
            8 => Self::Tls,
            9 => Self::Timeout,
            10 => Self::ConnectionLimit,
            11 => Self::InvalidState,
            12 => Self::PermissionDenied,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpRequest<'a> {
    pub request_id: u64,
    pub method: HttpMethod,
    pub timeout_ms: u32,
    pub url: &'a str,
    pub content_type: &'a str,
    pub body: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpRequestResult<'a> {
    pub request_id: u64,
    pub status: i32,
    pub failure: HttpFailure,
    pub status_code: u16,
    pub handle: u64,
    pub body_length: u32,
    pub headers_length: u32,
    pub content_type: &'a str,
}

pub fn encode_http_request(
    request_id: u64,
    method: HttpMethod,
    timeout_ms: u32,
    url: &str,
    content_type: &str,
    body: &[u8],
    out: &mut [u8],
) -> Result<usize, WireError> {
    validate_text(url, MAX_HTTP_URL_LEN)?;
    validate_text(content_type, MAX_HTTP_CONTENT_TYPE_LEN)?;
    if body.len() > MAX_HTTP_IPC_DATA_LEN {
        return Err(WireError::DataTooLarge(body.len()));
    }
    let payload = url
        .len()
        .checked_add(content_type.len())
        .and_then(|value| value.checked_add(body.len()))
        .ok_or(WireError::DataTooLarge(usize::MAX))?;
    let length = HTTP_REQUEST_BASE_LEN
        .checked_add(payload)
        .ok_or(WireError::DataTooLarge(payload))?;
    write_header(Opcode::HttpRequest, request_id, length, out)?;
    write_u16(out, 24, method.wire_value());
    write_u16(out, 26, 0);
    write_u32(out, 28, timeout_ms);
    write_u16(out, 32, url.len() as u16);
    write_u16(out, 34, content_type.len() as u16);
    write_u32(out, 36, body.len() as u32);
    write_u32(out, 40, 0);
    write_u32(out, 44, 0);
    let url_end = HTTP_REQUEST_BASE_LEN + url.len();
    let content_type_end = url_end + content_type.len();
    out[HTTP_REQUEST_BASE_LEN..url_end].copy_from_slice(url.as_bytes());
    out[url_end..content_type_end].copy_from_slice(content_type.as_bytes());
    out[content_type_end..length].copy_from_slice(body);
    Ok(length)
}

pub fn decode_http_request(bytes: &[u8]) -> Result<HttpRequest<'_>, WireError> {
    let header = Header::decode(bytes)?;
    expect_opcode(header.opcode, Opcode::HttpRequest)?;
    if bytes.len() < HTTP_REQUEST_BASE_LEN
        || read_u16(bytes, 26) != 0
        || read_u32(bytes, 40) != 0
        || read_u32(bytes, 44) != 0
    {
        return invalid_length(HTTP_REQUEST_BASE_LEN, bytes.len());
    }
    let method_raw = read_u16(bytes, 24);
    let method =
        HttpMethod::from_wire(method_raw).ok_or(WireError::UnknownHttpMethod(method_raw))?;
    let url_length = usize::from(read_u16(bytes, 32));
    let content_type_length = usize::from(read_u16(bytes, 34));
    let body_length = read_u32(bytes, 36) as usize;
    if url_length > MAX_HTTP_URL_LEN
        || content_type_length > MAX_HTTP_CONTENT_TYPE_LEN
        || body_length > MAX_HTTP_IPC_DATA_LEN
    {
        return Err(WireError::DataTooLarge(body_length));
    }
    let expected = HTTP_REQUEST_BASE_LEN
        .checked_add(url_length)
        .and_then(|value| value.checked_add(content_type_length))
        .and_then(|value| value.checked_add(body_length))
        .ok_or(WireError::DataTooLarge(usize::MAX))?;
    if bytes.len() != expected {
        return invalid_length(expected, bytes.len());
    }
    let url_end = HTTP_REQUEST_BASE_LEN + url_length;
    let content_type_end = url_end + content_type_length;
    let url = core::str::from_utf8(&bytes[HTTP_REQUEST_BASE_LEN..url_end])
        .map_err(|_| WireError::InvalidText)?;
    let content_type = core::str::from_utf8(&bytes[url_end..content_type_end])
        .map_err(|_| WireError::InvalidText)?;
    validate_text(url, MAX_HTTP_URL_LEN)?;
    validate_text(content_type, MAX_HTTP_CONTENT_TYPE_LEN)?;
    Ok(HttpRequest {
        request_id: header.request_id,
        method,
        timeout_ms: read_u32(bytes, 28),
        url,
        content_type,
        body: &bytes[content_type_end..],
    })
}

#[allow(clippy::too_many_arguments)]
pub fn encode_http_request_result(
    request_id: u64,
    status: i32,
    failure: HttpFailure,
    status_code: u16,
    handle: u64,
    body_length: u32,
    headers_length: u32,
    content_type: &str,
    out: &mut [u8],
) -> Result<usize, WireError> {
    validate_text(content_type, MAX_HTTP_CONTENT_TYPE_LEN)?;
    let length = HTTP_REQUEST_RESULT_BASE_LEN + content_type.len();
    write_header(Opcode::HttpRequestResult, request_id, length, out)?;
    write_i32(out, 24, status);
    write_u16(out, 28, failure.wire_value());
    write_u16(out, 30, status_code);
    write_u64(out, 32, handle);
    write_u32(out, 40, body_length);
    write_u32(out, 44, headers_length);
    write_u16(out, 48, content_type.len() as u16);
    write_u16(out, 50, 0);
    write_u32(out, 52, 0);
    out[HTTP_REQUEST_RESULT_BASE_LEN..length].copy_from_slice(content_type.as_bytes());
    Ok(length)
}

pub fn decode_http_request_result(bytes: &[u8]) -> Result<HttpRequestResult<'_>, WireError> {
    let header = Header::decode(bytes)?;
    expect_opcode(header.opcode, Opcode::HttpRequestResult)?;
    if bytes.len() < HTTP_REQUEST_RESULT_BASE_LEN
        || read_u16(bytes, 50) != 0
        || read_u32(bytes, 52) != 0
    {
        return invalid_length(HTTP_REQUEST_RESULT_BASE_LEN, bytes.len());
    }
    let failure_raw = read_u16(bytes, 28);
    let failure =
        HttpFailure::from_wire(failure_raw).ok_or(WireError::UnknownHttpFailure(failure_raw))?;
    let text_length = usize::from(read_u16(bytes, 48));
    if bytes.len() != HTTP_REQUEST_RESULT_BASE_LEN + text_length {
        return invalid_length(HTTP_REQUEST_RESULT_BASE_LEN + text_length, bytes.len());
    }
    let content_type = core::str::from_utf8(&bytes[HTTP_REQUEST_RESULT_BASE_LEN..])
        .map_err(|_| WireError::InvalidText)?;
    validate_text(content_type, MAX_HTTP_CONTENT_TYPE_LEN)?;
    Ok(HttpRequestResult {
        request_id: header.request_id,
        status: read_i32(bytes, 24),
        failure,
        status_code: read_u16(bytes, 30),
        handle: read_u64(bytes, 32),
        body_length: read_u32(bytes, 40),
        headers_length: read_u32(bytes, 44),
        content_type,
    })
}

pub fn encode_http_read(
    request_id: u64,
    handle: u64,
    maximum: u32,
    stream: HttpStream,
    out: &mut [u8],
) -> Result<usize, WireError> {
    if maximum as usize > MAX_HTTP_IPC_DATA_LEN {
        return Err(WireError::DataTooLarge(maximum as usize));
    }
    write_header(Opcode::HttpRead, request_id, HTTP_READ_REQUEST_LEN, out)?;
    write_u64(out, 24, handle);
    write_u32(out, 32, maximum);
    write_u16(out, 36, stream.wire_value());
    write_u16(out, 38, 0);
    Ok(HTTP_READ_REQUEST_LEN)
}

pub fn decode_http_read(bytes: &[u8]) -> Result<(u64, u64, u32, HttpStream), WireError> {
    let header = Header::decode(bytes)?;
    expect_opcode(header.opcode, Opcode::HttpRead)?;
    if bytes.len() != HTTP_READ_REQUEST_LEN || read_u16(bytes, 38) != 0 {
        return invalid_length(HTTP_READ_REQUEST_LEN, bytes.len());
    }
    let maximum = read_u32(bytes, 32);
    if maximum as usize > MAX_HTTP_IPC_DATA_LEN {
        return Err(WireError::DataTooLarge(maximum as usize));
    }
    let stream_raw = read_u16(bytes, 36);
    let stream =
        HttpStream::from_wire(stream_raw).ok_or(WireError::UnknownHttpStream(stream_raw))?;
    Ok((header.request_id, read_u64(bytes, 24), maximum, stream))
}

#[allow(clippy::too_many_arguments)]
pub fn encode_http_read_result(
    request_id: u64,
    opcode: Opcode,
    status: i32,
    failure: HttpFailure,
    handle: u64,
    complete: bool,
    data: &[u8],
    out: &mut [u8],
) -> Result<usize, WireError> {
    if !matches!(opcode, Opcode::HttpReadResult | Opcode::HttpCloseResult) {
        return Err(WireError::UnexpectedOpcode {
            expected: Opcode::HttpReadResult,
            actual: opcode,
        });
    }
    if data.len() > MAX_HTTP_IPC_DATA_LEN {
        return Err(WireError::DataTooLarge(data.len()));
    }
    let length = HTTP_READ_RESULT_BASE_LEN + data.len();
    write_header(opcode, request_id, length, out)?;
    write_i32(out, 24, status);
    write_u16(out, 28, failure.wire_value());
    write_u16(out, 30, u16::from(complete));
    write_u64(out, 32, handle);
    write_u32(out, 40, data.len() as u32);
    write_u32(out, 44, 0);
    out[HTTP_READ_RESULT_BASE_LEN..length].copy_from_slice(data);
    Ok(length)
}

pub fn decode_http_read_result(
    expected: Opcode,
    bytes: &[u8],
) -> Result<HttpReadResult<'_>, WireError> {
    let header = Header::decode(bytes)?;
    expect_opcode(header.opcode, expected)?;
    if bytes.len() < HTTP_READ_RESULT_BASE_LEN
        || read_u32(bytes, 44) != 0
        || read_u16(bytes, 30) > 1
    {
        return invalid_length(HTTP_READ_RESULT_BASE_LEN, bytes.len());
    }
    let failure_raw = read_u16(bytes, 28);
    let failure =
        HttpFailure::from_wire(failure_raw).ok_or(WireError::UnknownHttpFailure(failure_raw))?;
    let data_length = read_u32(bytes, 40) as usize;
    if data_length > MAX_HTTP_IPC_DATA_LEN || bytes.len() != HTTP_READ_RESULT_BASE_LEN + data_length
    {
        return invalid_length(HTTP_READ_RESULT_BASE_LEN + data_length, bytes.len());
    }
    Ok((
        header.request_id,
        read_i32(bytes, 24),
        failure,
        read_u64(bytes, 32),
        read_u16(bytes, 30) == 1,
        &bytes[HTTP_READ_RESULT_BASE_LEN..],
    ))
}

pub fn encode_http_close(request_id: u64, handle: u64, out: &mut [u8]) -> Result<usize, WireError> {
    write_header(Opcode::HttpClose, request_id, HTTP_CLOSE_REQUEST_LEN, out)?;
    write_u64(out, 24, handle);
    write_u64(out, 32, 0);
    Ok(HTTP_CLOSE_REQUEST_LEN)
}

pub fn decode_http_close(bytes: &[u8]) -> Result<(u64, u64), WireError> {
    let header = Header::decode(bytes)?;
    expect_opcode(header.opcode, Opcode::HttpClose)?;
    if bytes.len() != HTTP_CLOSE_REQUEST_LEN || read_u64(bytes, 32) != 0 {
        return invalid_length(HTTP_CLOSE_REQUEST_LEN, bytes.len());
    }
    Ok((header.request_id, read_u64(bytes, 24)))
}

fn validate_text(text: &str, maximum: usize) -> Result<(), WireError> {
    if text.len() > maximum {
        return Err(WireError::DataTooLarge(text.len()));
    }
    if text.as_bytes().iter().any(|byte| byte.is_ascii_control()) {
        return Err(WireError::InvalidText);
    }
    Ok(())
}

fn invalid_length<T>(declared: usize, actual: usize) -> Result<T, WireError> {
    Err(WireError::InvalidLength { declared, actual })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_and_bounds() {
        let mut bytes = [0u8; 8192];
        let length = encode_http_request(
            7,
            HttpMethod::Post,
            5000,
            "https://example.com/a",
            "application/json",
            b"{}",
            &mut bytes,
        )
        .unwrap();
        assert_eq!(
            decode_http_request(&bytes[..length]),
            Ok(HttpRequest {
                request_id: 7,
                method: HttpMethod::Post,
                timeout_ms: 5000,
                url: "https://example.com/a",
                content_type: "application/json",
                body: b"{}"
            })
        );
        assert!(matches!(
            encode_http_request(
                1,
                HttpMethod::Post,
                1,
                "https://a.test/",
                "",
                &[0; MAX_HTTP_IPC_DATA_LEN + 1],
                &mut bytes
            ),
            Err(WireError::DataTooLarge(_))
        ));
    }

    #[test]
    fn result_and_stream_operations_round_trip() {
        let mut bytes = [0u8; 8192];
        let length = encode_http_request_result(
            9,
            0,
            HttpFailure::None,
            200,
            44,
            2,
            12,
            "text/plain",
            &mut bytes,
        )
        .unwrap();
        assert_eq!(
            decode_http_request_result(&bytes[..length]),
            Ok(HttpRequestResult {
                request_id: 9,
                status: 0,
                failure: HttpFailure::None,
                status_code: 200,
                handle: 44,
                body_length: 2,
                headers_length: 12,
                content_type: "text/plain"
            })
        );
        encode_http_read(10, 44, 128, HttpStream::Body, &mut bytes).unwrap();
        assert_eq!(
            decode_http_read(&bytes[..HTTP_READ_REQUEST_LEN]),
            Ok((10, 44, 128, HttpStream::Body))
        );
        let length = encode_http_read_result(
            10,
            Opcode::HttpReadResult,
            0,
            HttpFailure::None,
            44,
            true,
            b"ok",
            &mut bytes,
        )
        .unwrap();
        assert_eq!(
            decode_http_read_result(Opcode::HttpReadResult, &bytes[..length]),
            Ok((10, 0, HttpFailure::None, 44, true, b"ok".as_slice()))
        );
        encode_http_close(11, 44, &mut bytes).unwrap();
        assert_eq!(
            decode_http_close(&bytes[..HTTP_CLOSE_REQUEST_LEN]),
            Ok((11, 44))
        );
    }

    #[test]
    fn reserved_unknown_and_short_buffers_are_rejected() {
        let mut bytes = [0u8; HTTP_READ_REQUEST_LEN];
        encode_http_read(1, 2, 3, HttpStream::Headers, &mut bytes).unwrap();
        bytes[38] = 1;
        assert!(decode_http_read(&bytes).is_err());
        assert!(matches!(
            encode_http_read(
                1,
                2,
                3,
                HttpStream::Body,
                &mut [0; HTTP_READ_REQUEST_LEN - 1]
            ),
            Err(WireError::BufferTooSmall { .. })
        ));
    }
}
