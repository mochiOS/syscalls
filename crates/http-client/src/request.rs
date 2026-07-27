use alloc::string::String;
use alloc::vec::Vec;

use crate::{HttpError, HttpsUrl, MAX_BODY_BYTES, MAX_HEADER_BYTES, MAX_HEADER_COUNT};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    const fn wire(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

pub fn encode_request(
    method: Method,
    url: &HttpsUrl,
    headers: &[Header<'_>],
    body: &[u8],
) -> Result<Vec<u8>, HttpError> {
    if body.len() > MAX_BODY_BYTES || (method == Method::Get && !body.is_empty()) {
        return Err(HttpError::BodyTooLarge);
    }
    if headers.len() > MAX_HEADER_COUNT {
        return Err(HttpError::TooManyHeaders);
    }
    let mut content_type = None;
    for header in headers {
        validate_header(header)?;
        if header.name.eq_ignore_ascii_case("host") {
            if !header.value.eq_ignore_ascii_case(&url.host_header()) {
                return Err(HttpError::HostnameMismatch);
            }
            continue;
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            let declared = header
                .value
                .parse::<usize>()
                .map_err(|_| HttpError::ContentLengthMismatch)?;
            if declared != body.len() {
                return Err(HttpError::ContentLengthMismatch);
            }
            continue;
        }
        if header.name.eq_ignore_ascii_case("connection") {
            if !header.value.eq_ignore_ascii_case("close") {
                return Err(HttpError::InvalidHeaderValue);
            }
            continue;
        }
        if header.name.eq_ignore_ascii_case("content-type") {
            content_type = Some(header.value);
        }
    }
    let mut request = String::new();
    push_line(
        &mut request,
        &alloc::format!("{} {} HTTP/1.1", method.wire(), url.path()),
    )?;
    push_line(&mut request, &alloc::format!("Host: {}", url.host_header()))?;
    push_line(&mut request, "User-Agent: mochiOS/0.1")?;
    push_line(&mut request, "Accept: */*")?;
    push_line(&mut request, "Connection: close")?;
    for header in headers {
        if is_managed(header.name) {
            continue;
        }
        push_line(
            &mut request,
            &alloc::format!("{}: {}", header.name, header.value),
        )?;
    }
    if method == Method::Post {
        if content_type.is_none() {
            push_line(&mut request, "Content-Type: application/octet-stream")?;
        }
        push_line(
            &mut request,
            &alloc::format!("Content-Length: {}", body.len()),
        )?;
    }
    request.push_str("\r\n");
    if request.len() > MAX_HEADER_BYTES {
        return Err(HttpError::HeadersTooLarge);
    }
    let mut result = request.into_bytes();
    result.extend_from_slice(body);
    Ok(result)
}

fn push_line(destination: &mut String, line: &str) -> Result<(), HttpError> {
    destination.push_str(line);
    destination.push_str("\r\n");
    if destination.len() > MAX_HEADER_BYTES {
        Err(HttpError::HeadersTooLarge)
    } else {
        Ok(())
    }
}

fn validate_header(header: &Header<'_>) -> Result<(), HttpError> {
    if header.name.is_empty()
        || !header.name.as_bytes().iter().all(|byte| {
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
        return Err(HttpError::InvalidHeaderName);
    }
    if header.value.as_bytes().iter().any(|byte| {
        *byte == b'\r' || *byte == b'\n' || (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f
    }) {
        return Err(HttpError::InvalidHeaderValue);
    }
    Ok(())
}

fn is_managed(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("user-agent")
        || name.eq_ignore_ascii_case("accept")
}
