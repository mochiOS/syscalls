use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::{
    HttpError, MAX_BODY_BYTES, MAX_CHUNK_BYTES, MAX_HEADER_BYTES, MAX_HEADER_COUNT,
    MAX_HEADER_LINE_LEN, MAX_STATUS_LINE_LEN, MAX_TRAILER_BYTES,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status_code: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

pub struct ResponseDecoder {
    bytes: Vec<u8>,
}

impl ResponseDecoder {
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), HttpError> {
        let maximum = MAX_HEADER_BYTES
            .checked_add(MAX_BODY_BYTES)
            .and_then(|value| value.checked_add(MAX_TRAILER_BYTES))
            .ok_or(HttpError::BodyTooLarge)?;
        if self.bytes.len().saturating_add(bytes.len()) > maximum {
            return Err(HttpError::BodyTooLarge);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub fn decode(&self, end_of_stream: bool) -> Result<HttpResponse, HttpError> {
        decode_response(&self.bytes, end_of_stream)
    }
}

impl Default for ResponseDecoder {
    fn default() -> Self {
        Self::new()
    }
}

fn decode_response(bytes: &[u8], end_of_stream: bool) -> Result<HttpResponse, HttpError> {
    let header_end = find_sequence(bytes, b"\r\n\r\n").ok_or({
        if bytes.len() > MAX_HEADER_BYTES {
            HttpError::HeadersTooLarge
        } else if end_of_stream {
            HttpError::UnexpectedEnd
        } else {
            HttpError::Incomplete
        }
    })?;
    let header_bytes = header_end + 4;
    if header_bytes > MAX_HEADER_BYTES {
        return Err(HttpError::HeadersTooLarge);
    }
    let head =
        core::str::from_utf8(&bytes[..header_end]).map_err(|_| HttpError::InvalidResponseHeader)?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(HttpError::InvalidStatusLine)?;
    let (status_code, reason) = parse_status_line(status_line)?;
    let mut headers = Vec::new();
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        if line.len() > MAX_HEADER_LINE_LEN {
            return Err(HttpError::HeadersTooLarge);
        }
        if headers.len() >= MAX_HEADER_COUNT {
            return Err(HttpError::TooManyHeaders);
        }
        let (name, value) = parse_header(line)?;
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .parse::<usize>()
                .map_err(|_| HttpError::ConflictingContentLength)?;
            if parsed > MAX_BODY_BYTES {
                return Err(HttpError::BodyTooLarge);
            }
            if content_length.is_some_and(|previous| previous != parsed) {
                return Err(HttpError::ConflictingContentLength);
            }
            content_length = Some(parsed);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if !value.eq_ignore_ascii_case("chunked") || chunked {
                return Err(HttpError::UnsupportedTransferEncoding);
            }
            chunked = true;
        }
        headers.push((name.to_ascii_lowercase(), value.to_string()));
    }
    if chunked && content_length.is_some() {
        return Err(HttpError::ConflictingFraming);
    }
    let payload = &bytes[header_bytes..];
    let body = if response_has_no_body(status_code) {
        if !payload.is_empty() {
            return Err(HttpError::TrailingData);
        }
        Vec::new()
    } else if chunked {
        decode_chunked(payload, end_of_stream)?
    } else if let Some(length) = content_length {
        if payload.len() < length {
            return Err(if end_of_stream {
                HttpError::UnexpectedEnd
            } else {
                HttpError::Incomplete
            });
        }
        if payload.len() != length {
            return Err(HttpError::TrailingData);
        }
        payload.to_vec()
    } else {
        if !end_of_stream {
            return Err(HttpError::Incomplete);
        }
        if payload.len() > MAX_BODY_BYTES {
            return Err(HttpError::BodyTooLarge);
        }
        payload.to_vec()
    };
    Ok(HttpResponse {
        status_code,
        reason: reason.to_string(),
        headers,
        body,
    })
}

fn parse_status_line(line: &str) -> Result<(u16, &str), HttpError> {
    if line.len() > MAX_STATUS_LINE_LEN {
        return Err(HttpError::InvalidStatusLine);
    }
    let mut parts = line.splitn(3, ' ');
    if parts.next() != Some("HTTP/1.1") {
        return Err(HttpError::UnsupportedHttpVersion);
    }
    let raw_status = parts.next().ok_or(HttpError::InvalidStatusLine)?;
    if raw_status.len() != 3 || !raw_status.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HttpError::InvalidStatusCode);
    }
    let status = raw_status
        .parse::<u16>()
        .map_err(|_| HttpError::InvalidStatusCode)?;
    if !(100..=599).contains(&status) {
        return Err(HttpError::InvalidStatusCode);
    }
    let reason = parts.next().unwrap_or("");
    if reason
        .as_bytes()
        .iter()
        .any(|byte| *byte < 0x20 || *byte == 0x7f)
    {
        return Err(HttpError::InvalidStatusLine);
    }
    Ok((status, reason))
}

fn parse_header(line: &str) -> Result<(&str, &str), HttpError> {
    let (name, value) = line
        .split_once(':')
        .ok_or(HttpError::InvalidResponseHeader)?;
    if name.is_empty()
        || !name.as_bytes().iter().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return Err(HttpError::InvalidResponseHeader);
    }
    let value = value.trim_matches([' ', '\t']);
    if value
        .as_bytes()
        .iter()
        .any(|byte| (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f)
    {
        return Err(HttpError::InvalidResponseHeader);
    }
    Ok((name, value))
}

fn decode_chunked(payload: &[u8], end_of_stream: bool) -> Result<Vec<u8>, HttpError> {
    let mut cursor = 0usize;
    let mut body = Vec::new();
    loop {
        let line_end = find_sequence(&payload[cursor..], b"\r\n").ok_or({
            if end_of_stream {
                HttpError::UnexpectedEnd
            } else {
                HttpError::Incomplete
            }
        })?;
        if line_end > MAX_HEADER_LINE_LEN {
            return Err(HttpError::InvalidChunkSize);
        }
        let line = core::str::from_utf8(&payload[cursor..cursor + line_end])
            .map_err(|_| HttpError::InvalidChunkSize)?;
        let size_text = line.split(';').next().ok_or(HttpError::InvalidChunkSize)?;
        if size_text.is_empty() || size_text.len() > 16 {
            return Err(HttpError::InvalidChunkSize);
        }
        let size = usize::from_str_radix(size_text, 16).map_err(|_| HttpError::InvalidChunkSize)?;
        if size > MAX_CHUNK_BYTES {
            return Err(HttpError::ChunkTooLarge);
        }
        cursor = cursor
            .checked_add(line_end + 2)
            .ok_or(HttpError::InvalidChunkSize)?;
        if size == 0 {
            let trailer_end = find_sequence(&payload[cursor..], b"\r\n\r\n")
                .map(|offset| offset + 4)
                .or_else(|| payload[cursor..].starts_with(b"\r\n").then_some(2))
                .ok_or({
                    if end_of_stream {
                        HttpError::UnexpectedEnd
                    } else {
                        HttpError::Incomplete
                    }
                })?;
            if trailer_end > MAX_TRAILER_BYTES {
                return Err(HttpError::TrailersTooLarge);
            }
            validate_trailers(&payload[cursor..cursor + trailer_end])?;
            cursor += trailer_end;
            if cursor != payload.len() {
                return Err(HttpError::TrailingData);
            }
            return Ok(body);
        }
        let data_end = cursor.checked_add(size).ok_or(HttpError::BodyTooLarge)?;
        let terminator_end = data_end.checked_add(2).ok_or(HttpError::BodyTooLarge)?;
        if terminator_end > payload.len() {
            return Err(if end_of_stream {
                HttpError::UnexpectedEnd
            } else {
                HttpError::Incomplete
            });
        }
        if &payload[data_end..terminator_end] != b"\r\n" {
            return Err(HttpError::InvalidChunkTerminator);
        }
        if body.len().saturating_add(size) > MAX_BODY_BYTES {
            return Err(HttpError::BodyTooLarge);
        }
        body.extend_from_slice(&payload[cursor..data_end]);
        cursor = terminator_end;
    }
}

fn validate_trailers(bytes: &[u8]) -> Result<(), HttpError> {
    let content = if bytes == b"\r\n" {
        return Ok(());
    } else {
        bytes
            .strip_suffix(b"\r\n\r\n")
            .ok_or(HttpError::InvalidResponseHeader)?
    };
    let text = core::str::from_utf8(content).map_err(|_| HttpError::InvalidResponseHeader)?;
    let mut count = 0usize;
    for line in text.split("\r\n") {
        count += 1;
        if count > MAX_HEADER_COUNT || line.len() > MAX_HEADER_LINE_LEN {
            return Err(HttpError::TrailersTooLarge);
        }
        let _ = parse_header(line)?;
    }
    Ok(())
}

fn response_has_no_body(status: u16) -> bool {
    (100..200).contains(&status) || status == 204 || status == 304
}

fn find_sequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
