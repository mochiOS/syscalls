use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::{HttpError, MAX_HOSTNAME_LEN, MAX_PATH_LEN, MAX_REDIRECTS, MAX_URL_LEN};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpsUrl {
    original: String,
    hostname: String,
    port: u16,
    path: String,
}

impl HttpsUrl {
    pub fn parse(input: &str) -> Result<Self, HttpError> {
        if input.len() > MAX_URL_LEN {
            return Err(HttpError::UrlTooLong);
        }
        if input
            .as_bytes()
            .iter()
            .any(|byte| byte.is_ascii_control() || *byte == b' ')
        {
            return Err(HttpError::InvalidUrl);
        }
        if input.contains('#') {
            return Err(HttpError::FragmentForbidden);
        }
        let authority_and_path = input
            .strip_prefix("https://")
            .ok_or(HttpError::UnsupportedScheme)?;
        let split = authority_and_path
            .find(['/', '?'])
            .unwrap_or(authority_and_path.len());
        let authority = &authority_and_path[..split];
        if authority.contains('@') {
            return Err(HttpError::UserInfoForbidden);
        }
        let (hostname, port) = parse_authority(authority)?;
        let path = match authority_and_path.get(split..) {
            Some("") | None => "/",
            Some(value) if value.starts_with('?') => {
                return build(input, hostname, port, alloc::format!("/{value}"));
            }
            Some(value) => value,
        };
        build(input, hostname, port, path.to_string())
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn as_str(&self) -> &str {
        &self.original
    }

    pub fn host_header(&self) -> String {
        if self.port == 443 {
            self.hostname.clone()
        } else {
            alloc::format!("{}:{}", self.hostname, self.port)
        }
    }
}

fn build(input: &str, hostname: String, port: u16, path: String) -> Result<HttpsUrl, HttpError> {
    if path.len() > MAX_PATH_LEN || !path.starts_with('/') {
        return Err(HttpError::InvalidPath);
    }
    Ok(HttpsUrl {
        original: input.to_string(),
        hostname,
        port,
        path,
    })
}

fn parse_authority(authority: &str) -> Result<(String, u16), HttpError> {
    if authority.is_empty() || authority.starts_with('[') || authority.ends_with('.') {
        return Err(HttpError::InvalidHostname);
    }
    let (hostname, port) = match authority.rsplit_once(':') {
        Some((host, raw_port)) => {
            if host.contains(':') || raw_port.is_empty() {
                return Err(HttpError::InvalidPort);
            }
            let port = raw_port
                .parse::<u16>()
                .map_err(|_| HttpError::InvalidPort)?;
            if port == 0 {
                return Err(HttpError::InvalidPort);
            }
            (host, port)
        }
        None => (authority, 443),
    };
    validate_hostname(hostname)?;
    Ok((hostname.to_ascii_lowercase(), port))
}

fn validate_hostname(hostname: &str) -> Result<(), HttpError> {
    if hostname.len() > MAX_HOSTNAME_LEN
        || hostname.parse::<core::net::Ipv4Addr>().is_ok()
        || hostname.contains('*')
    {
        return Err(HttpError::InvalidHostname);
    }
    let mut labels = hostname.split('.');
    if labels.any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    }) {
        return Err(HttpError::InvalidHostname);
    }
    Ok(())
}

pub struct RedirectTracker {
    visited: Vec<String>,
}

impl RedirectTracker {
    pub const fn new() -> Self {
        Self {
            visited: Vec::new(),
        }
    }

    pub fn follow(&mut self, url: &HttpsUrl, location: &str) -> Result<HttpsUrl, HttpError> {
        if location.starts_with("http://") {
            return Err(HttpError::RedirectDowngrade);
        }
        let next = if location.starts_with("https://") {
            HttpsUrl::parse(location)?
        } else if location.starts_with('/') {
            let authority = url.host_header();
            HttpsUrl::parse(&alloc::format!("https://{authority}{location}"))?
        } else {
            return Err(HttpError::RedirectUnsupported);
        };
        if self.visited.len() >= MAX_REDIRECTS {
            return Err(HttpError::RedirectLimit);
        }
        if self.visited.iter().any(|value| value == next.as_str()) {
            return Err(HttpError::RedirectLoop);
        }
        self.visited.push(next.as_str().to_string());
        Ok(next)
    }
}

impl Default for RedirectTracker {
    fn default() -> Self {
        Self::new()
    }
}
