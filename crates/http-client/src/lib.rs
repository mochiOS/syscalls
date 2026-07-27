#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod request;
mod response;
mod url;

pub use request::{Header, Method, encode_request};
pub use response::{HttpResponse, ResponseDecoder};
pub use url::{HttpsUrl, RedirectTracker};

pub const MAX_URL_LEN: usize = 2_048;
pub const MAX_HOSTNAME_LEN: usize = 253;
pub const MAX_PATH_LEN: usize = 1_536;
pub const MAX_STATUS_LINE_LEN: usize = 1_024;
pub const MAX_HEADER_LINE_LEN: usize = 4_096;
pub const MAX_HEADER_COUNT: usize = 64;
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_TRAILER_BYTES: usize = 8 * 1024;
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
pub const MAX_CHUNK_BYTES: usize = 256 * 1024;
pub const MAX_REDIRECTS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpError {
    InvalidUrl,
    UnsupportedScheme,
    UserInfoForbidden,
    FragmentForbidden,
    InvalidHostname,
    InvalidPort,
    InvalidPath,
    UrlTooLong,
    InvalidMethod,
    InvalidHeaderName,
    InvalidHeaderValue,
    HostnameMismatch,
    ContentLengthMismatch,
    HeadersTooLarge,
    TooManyHeaders,
    InvalidStatusLine,
    UnsupportedHttpVersion,
    InvalidStatusCode,
    InvalidResponseHeader,
    ConflictingContentLength,
    ConflictingFraming,
    UnsupportedTransferEncoding,
    InvalidChunkSize,
    ChunkTooLarge,
    InvalidChunkTerminator,
    TrailersTooLarge,
    BodyTooLarge,
    UnexpectedEnd,
    TrailingData,
    Incomplete,
    RedirectUnsupported,
    RedirectLoop,
    RedirectLimit,
    RedirectDowngrade,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_https_urls_and_rejects_unsafe_forms() {
        let url = HttpsUrl::parse("https://Example.COM:8443/health?q=1").unwrap();
        assert_eq!(url.hostname(), "example.com");
        assert_eq!(url.port(), 8443);
        assert_eq!(url.path(), "/health?q=1");
        assert_eq!(
            HttpsUrl::parse("http://example.com/"),
            Err(HttpError::UnsupportedScheme)
        );
        assert_eq!(
            HttpsUrl::parse("https://u@example.com/"),
            Err(HttpError::UserInfoForbidden)
        );
        assert_eq!(
            HttpsUrl::parse("https://127.0.0.1/"),
            Err(HttpError::InvalidHostname)
        );
        assert_eq!(
            HttpsUrl::parse("https://example.com/#x"),
            Err(HttpError::FragmentForbidden)
        );
    }

    #[test]
    fn encodes_get_and_post_without_header_injection() {
        let url = HttpsUrl::parse("https://example.com/api").unwrap();
        let get = encode_request(Method::Get, &url, &[], &[]).unwrap();
        assert!(get.starts_with(b"GET /api HTTP/1.1\r\nHost: example.com\r\n"));
        assert!(get.ends_with(b"Connection: close\r\n\r\n"));
        let post = encode_request(
            Method::Post,
            &url,
            &[Header {
                name: "Content-Type",
                value: "application/json",
            }],
            b"{}",
        )
        .unwrap();
        assert!(
            post.windows(19)
                .any(|value| value == b"Content-Length: 2\r\n")
        );
        assert!(post.ends_with(b"\r\n\r\n{}"));
        assert_eq!(
            encode_request(
                Method::Get,
                &url,
                &[Header {
                    name: "X",
                    value: "a\r\nb"
                }],
                &[]
            ),
            Err(HttpError::InvalidHeaderValue)
        );
        assert_eq!(
            encode_request(
                Method::Get,
                &url,
                &[Header {
                    name: "Host",
                    value: "other.test"
                }],
                &[]
            ),
            Err(HttpError::HostnameMismatch)
        );
        assert_eq!(
            encode_request(
                Method::Post,
                &url,
                &[Header {
                    name: "Content-Length",
                    value: "3"
                }],
                b"{}"
            ),
            Err(HttpError::ContentLengthMismatch)
        );
        assert_eq!(
            encode_request(
                Method::Get,
                &url,
                &[Header {
                    name: "bad name",
                    value: "ok"
                }],
                &[]
            ),
            Err(HttpError::InvalidHeaderName)
        );
    }

    #[test]
    fn parses_content_length_and_header_names_case_insensitively() {
        let mut decoder = ResponseDecoder::new();
        decoder
            .feed(
                b"HTTP/1.1 200 OK\r\ncOnTeNt-TyPe: application/json\r\nContent-Length: 2\r\n\r\n{}",
            )
            .unwrap();
        let response = decoder.decode(false).unwrap();
        assert_eq!(response.status_code, 200);
        assert_eq!(response.header("CONTENT-TYPE"), Some("application/json"));
        assert_eq!(response.body, b"{}");
    }

    #[test]
    fn content_length_is_strict_and_bounded() {
        let mut decoder = ResponseDecoder::new();
        decoder
            .feed(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nabc")
            .unwrap();
        assert_eq!(
            decoder.decode(true),
            Err(HttpError::ConflictingContentLength)
        );
        let mut decoder = ResponseDecoder::new();
        decoder
            .feed(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab")
            .unwrap();
        assert_eq!(decoder.decode(true), Err(HttpError::UnexpectedEnd));
        let oversized = alloc::format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let mut decoder = ResponseDecoder::new();
        decoder.feed(oversized.as_bytes()).unwrap();
        assert_eq!(decoder.decode(false), Err(HttpError::BodyTooLarge));

        let mut duplicate = ResponseDecoder::new();
        duplicate
            .feed(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nOK")
            .unwrap();
        assert_eq!(duplicate.decode(false).unwrap().body, b"OK");
    }

    #[test]
    fn parses_chunked_body_extensions_and_trailers() {
        let mut decoder = ResponseDecoder::new();
        decoder.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4;x=y\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Checksum: ok\r\n\r\n").unwrap();
        let response = decoder.decode(false).unwrap();
        assert_eq!(response.body, b"Wikipedia");
        let mut invalid = ResponseDecoder::new();
        invalid
            .feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n")
            .unwrap();
        assert_eq!(invalid.decode(true), Err(HttpError::InvalidChunkSize));
    }

    #[test]
    fn rejects_ambiguous_framing_and_excess_headers() {
        let mut decoder = ResponseDecoder::new();
        decoder.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n").unwrap();
        assert_eq!(decoder.decode(false), Err(HttpError::ConflictingFraming));
        let mut response = alloc::string::String::from("HTTP/1.1 200 OK\r\n");
        for _ in 0..=MAX_HEADER_COUNT {
            response.push_str("X: y\r\n");
        }
        response.push_str("\r\n");
        let mut decoder = ResponseDecoder::new();
        decoder.feed(response.as_bytes()).unwrap();
        assert_eq!(decoder.decode(true), Err(HttpError::TooManyHeaders));
    }

    #[test]
    fn rejects_malformed_status_and_response_headers() {
        for (response, expected) in [
            (
                b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice(),
                HttpError::UnsupportedHttpVersion,
            ),
            (
                b"HTTP/1.1 99 Bad\r\nContent-Length: 0\r\n\r\n".as_slice(),
                HttpError::InvalidStatusCode,
            ),
            (
                b"HTTP/1.1 200 OK\r\nMissing-Colon\r\n\r\n".as_slice(),
                HttpError::InvalidResponseHeader,
            ),
            (
                b"HTTP/1.1 200 OK\r\nBad Header: value\r\n\r\n".as_slice(),
                HttpError::InvalidResponseHeader,
            ),
        ] {
            let mut decoder = ResponseDecoder::new();
            decoder.feed(response).unwrap();
            assert_eq!(decoder.decode(true), Err(expected));
        }

        let long_status =
            alloc::format!("HTTP/1.1 200 {}\r\n\r\n", "x".repeat(MAX_STATUS_LINE_LEN));
        let mut decoder = ResponseDecoder::new();
        decoder.feed(long_status.as_bytes()).unwrap();
        assert_eq!(decoder.decode(true), Err(HttpError::InvalidStatusLine));

        let long_header = alloc::format!(
            "HTTP/1.1 200 OK\r\nX: {}\r\n\r\n",
            "x".repeat(MAX_HEADER_LINE_LEN)
        );
        let mut decoder = ResponseDecoder::new();
        decoder.feed(long_header.as_bytes()).unwrap();
        assert_eq!(decoder.decode(true), Err(HttpError::HeadersTooLarge));
    }

    #[test]
    fn chunk_size_body_and_trailer_limits_are_enforced() {
        let oversized_chunk = alloc::format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            MAX_CHUNK_BYTES + 1
        );
        let mut decoder = ResponseDecoder::new();
        decoder.feed(oversized_chunk.as_bytes()).unwrap();
        assert_eq!(decoder.decode(false), Err(HttpError::ChunkTooLarge));

        let mut decoder = ResponseDecoder::new();
        decoder
            .feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx!\r\n0\r\n\r\n")
            .unwrap();
        assert_eq!(decoder.decode(true), Err(HttpError::InvalidChunkTerminator));

        let trailer = "X: y\r\n".repeat(MAX_TRAILER_BYTES / 6 + 1);
        let response = alloc::format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n{trailer}\r\n"
        );
        let mut decoder = ResponseDecoder::new();
        decoder.feed(response.as_bytes()).unwrap();
        assert_eq!(decoder.decode(true), Err(HttpError::TrailersTooLarge));
    }

    #[test]
    fn connection_close_framing_is_bounded_and_requires_eof() {
        let mut decoder = ResponseDecoder::new();
        decoder
            .feed(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody")
            .unwrap();
        assert_eq!(decoder.decode(false), Err(HttpError::Incomplete));
        assert_eq!(decoder.decode(true).unwrap().body, b"body");
    }

    #[test]
    fn redirect_policy_rejects_downgrade_loops_and_excess() {
        let start = HttpsUrl::parse("https://example.com/a").unwrap();
        let mut tracker = RedirectTracker::new();
        assert_eq!(
            tracker.follow(&start, "http://example.com/b"),
            Err(HttpError::RedirectDowngrade)
        );
        let next = tracker.follow(&start, "/b").unwrap();
        assert_eq!(tracker.follow(&next, "/b"), Err(HttpError::RedirectLoop));
        tracker.follow(&next, "/c").unwrap();
        tracker.follow(&next, "/d").unwrap();
        assert_eq!(tracker.follow(&next, "/e"), Err(HttpError::RedirectLimit));
    }
}
