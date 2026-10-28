//! POSIX name/service translation policy. Backends supply name-service data
//! and interface configuration; this module owns no endpoints, FDs or globals.
//! Numeric paths never consult a name service. Output is streamed to a caller
//! that owns allocation and must discard partial output on an error.
use crate::internet::{AF_INET, AF_INET6, Address};

pub mod database;
pub mod dns;

pub const AF_UNSPEC: i32 = 0;
pub const AI_PASSIVE: i32 = 1;
pub const AI_CANONNAME: i32 = 2;
pub const AI_NUMERICHOST: i32 = 4;
pub const AI_V4MAPPED: i32 = 8;
pub const AI_ALL: i32 = 16;
pub const AI_ADDRCONFIG: i32 = 32;
pub const AI_NUMERICSERV: i32 = 1024;
pub const NI_NUMERICHOST: i32 = 1;
pub const NI_NUMERICSERV: i32 = 2;
pub const NI_NOFQDN: i32 = 4;
pub const NI_NAMEREQD: i32 = 8;
pub const NI_DGRAM: i32 = 16;
pub const NI_MAXHOST: usize = 1025;
pub const NI_MAXSERV: usize = 32;
const AI_FLAGS: i32 = AI_PASSIVE
    | AI_CANONNAME
    | AI_NUMERICHOST
    | AI_V4MAPPED
    | AI_ALL
    | AI_ADDRCONFIG
    | AI_NUMERICSERV;
const NI_FLAGS: i32 = NI_NUMERICHOST | NI_NUMERICSERV | NI_NOFQDN | NI_NAMEREQD | NI_DGRAM;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BadFlags,
    NoName,
    Again,
    Fail,
    Family,
    SockType,
    Service,
    Memory,
    System(i32),
    Overflow,
}
impl Error {
    /// Application ABI values; these are not native syscall errors.
    pub const fn code(self) -> i32 {
        match self {
            Self::BadFlags => -1,
            Self::NoName => -2,
            Self::Again => -3,
            Self::Fail => -4,
            Self::Family => -6,
            Self::SockType => -7,
            Self::Service => -8,
            Self::Memory => -10,
            Self::System(_) => -11,
            Self::Overflow => -12,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hints {
    pub flags: i32,
    pub family: i32,
    pub socktype: i32,
    pub protocol: i32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}
impl Transport {
    pub const fn socktype(self) -> i32 {
        match self {
            Self::Tcp => 1,
            Self::Udp => 2,
        }
    }
    pub const fn protocol(self) -> i32 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Configuration {
    pub ipv4: bool,
    pub ipv6: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopedAddress {
    pub address: Address,
    pub scope: u32,
}
impl From<Address> for ScopedAddress {
    fn from(address: Address) -> Self {
        Self { address, scope: 0 }
    }
}
impl ScopedAddress {
    pub const fn family(self) -> i32 {
        match self.address {
            Address::V4(_) => AF_INET,
            Address::V6(_) => AF_INET6,
        }
    }
    pub fn format(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.address.format(out).map_err(|_| Error::Overflow)?;
        if self.scope == 0 {
            return Ok(n);
        }
        if self.family() != AF_INET6 {
            return Err(Error::Family);
        }
        *out.get_mut(n).ok_or(Error::Overflow)? = b'%';
        Ok(n + 1 + number(self.scope, out.get_mut(n + 1..).ok_or(Error::Overflow)?)?)
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Host<'a> {
    pub address: ScopedAddress,
    pub canonical: Option<&'a [u8]>,
}
#[derive(Clone, Copy, Debug)]
pub struct Entry<'a> {
    pub address: ScopedAddress,
    pub port: u16,
    pub transport: Transport,
    pub canonical: Option<&'a [u8]>,
}
#[derive(Clone, Copy, Debug)]
pub struct Reverse {
    pub length: usize,
    pub local: bool,
}

/// No identity supplied here may impersonate another process. Implementations
/// obtain resource access through their own explicitly delegated authority.
pub trait Backend {
    /// Configured non-loopback families, not a claim about DNS record types.
    fn configuration(&mut self) -> Result<Configuration, Error>;
    fn scope(&mut self, interface: &[u8]) -> Result<Option<u32>, Error>;
    fn host(
        &mut self,
        name: &[u8],
        family: i32,
        emit: &mut dyn FnMut(Host<'_>) -> Result<(), Error>,
    ) -> Result<(), Error>;
    fn service(&mut self, name: &[u8], transport: Transport) -> Result<Option<u16>, Error>;
    fn reverse(&mut self, address: ScopedAddress, out: &mut [u8])
    -> Result<Option<Reverse>, Error>;
    fn service_name(
        &mut self,
        port: u16,
        transport: Transport,
        out: &mut [u8],
    ) -> Result<Option<usize>, Error>;
}

fn text(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.len() < NI_MAXHOST && !bytes.contains(&0)
}
fn absent<T>(result: Result<Option<T>, Error>) -> Result<Option<T>, Error> {
    match result {
        Err(Error::NoName) => Ok(None),
        result => result,
    }
}
fn number(mut n: u32, out: &mut [u8]) -> Result<usize, Error> {
    let mut digits = [0; 10];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    let n = digits.len() - start;
    out.get_mut(..n)
        .ok_or(Error::Overflow)?
        .copy_from_slice(&digits[start..]);
    Ok(n)
}
fn decimal(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0u32, |n, b| {
        if !b.is_ascii_digit() {
            return None;
        }
        n.checked_mul(10)?.checked_add(u32::from(*b - b'0'))
    })
}

/// inet_addr-style numeric input required by getaddrinfo, independent of the
/// deliberately stricter inet_pton API. No signs or surrounding whitespace.
pub fn ipv4_number(bytes: &[u8]) -> Option<[u8; 4]> {
    let mut parts = [0u32; 4];
    let mut count = 0;
    for part in bytes.split(|b| *b == b'.') {
        if count == 4 || part.is_empty() {
            return None;
        }
        let (base, digits) = if part.starts_with(b"0x") || part.starts_with(b"0X") {
            (16u32, &part[2..])
        } else if part.len() > 1 && part[0] == b'0' {
            (8, &part[1..])
        } else {
            (10, part)
        };
        if digits.is_empty() {
            return None;
        }
        let value = digits.iter().try_fold(0u32, |n, b| {
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return None,
            } as u32;
            if digit >= base {
                return None;
            }
            n.checked_mul(base)?.checked_add(digit)
        })?;
        parts[count] = value;
        count += 1;
    }
    if count == 0 {
        return None;
    }
    let remaining = 5 - count;
    if remaining < 4 && parts[count - 1] >= 1u32 << (remaining * 8) {
        return None;
    }
    let mut result = parts[count - 1];
    for (i, value) in parts[..count - 1].iter().enumerate() {
        if *value > 255 {
            return None;
        }
        result |= value << (24 - i * 8);
    }
    Some(result.to_be_bytes())
}

fn numeric<B: Backend>(backend: &mut B, bytes: &[u8]) -> Result<Option<ScopedAddress>, Error> {
    if let Some(v4) = ipv4_number(bytes) {
        return Ok(Some(Address::V4(v4).into()));
    }
    let mut split = bytes.split(|b| *b == b'%');
    let first = split.next().unwrap_or_default();
    let zone = split.next();
    if split.next().is_some() {
        return Err(Error::NoName);
    }
    let Some(address) = Address::parse(AF_INET6, first).map_err(|_| Error::Family)? else {
        return if zone.is_some() || bytes.contains(&b':') {
            Err(Error::NoName)
        } else {
            Ok(None)
        };
    };
    let scope = match zone {
        None => 0,
        Some(zone) if zone.is_empty() => return Err(Error::NoName),
        Some(zone) if zone.iter().all(u8::is_ascii_digit) => decimal(zone).ok_or(Error::NoName)?,
        Some(zone) => backend
            .scope(zone)?
            .filter(|n| *n != 0)
            .ok_or(Error::NoName)?,
    };
    Ok(Some(ScopedAddress { address, scope }))
}
fn mapped(address: ScopedAddress) -> ScopedAddress {
    let Address::V4(v4) = address.address else {
        return address;
    };
    let mut bytes = [0; 16];
    bytes[10..12].fill(255);
    bytes[12..].copy_from_slice(&v4);
    Address::V6(bytes).into()
}

/// Callbacks may receive a prefix before a later lookup/allocation failure.
/// Only a successful return commits the complete set to the application.
pub fn getaddrinfo<B: Backend>(
    backend: &mut B,
    node: Option<&[u8]>,
    service: Option<&[u8]>,
    hints: Hints,
    emit: &mut dyn FnMut(Entry<'_>) -> Result<(), Error>,
) -> Result<usize, Error> {
    if hints.flags & !AI_FLAGS != 0 {
        return Err(Error::BadFlags);
    }
    if !matches!(hints.family, AF_UNSPEC | AF_INET | AF_INET6) {
        return Err(Error::Family);
    }
    if !matches!(hints.socktype, 0 | 1 | 2) {
        return Err(Error::SockType);
    }
    if node.is_none() && service.is_none() {
        return Err(Error::NoName);
    }
    if node.is_some_and(|n| !text(n)) {
        return Err(Error::NoName);
    }
    let mut services = [(Transport::Tcp, 0); 2];
    let mut nservices = 0;
    let numeric_port = match service {
        None => Some(0),
        Some(s) if s.is_empty() || s.contains(&0) => return Err(Error::Service),
        Some(s) if s.iter().all(u8::is_ascii_digit) => Some(
            decimal(s)
                .and_then(|n| u16::try_from(n).ok())
                .ok_or(Error::Service)?,
        ),
        Some(_) if hints.flags & AI_NUMERICSERV != 0 => return Err(Error::NoName),
        Some(_) => None,
    };
    for transport in [Transport::Tcp, Transport::Udp] {
        if hints.socktype != 0 && hints.socktype != transport.socktype() {
            continue;
        }
        if hints.protocol != 0 && hints.protocol != transport.protocol() {
            continue;
        }
        let port = match numeric_port {
            Some(p) => Some(p),
            None => absent(backend.service(service.unwrap(), transport))?,
        };
        if let Some(port) = port {
            services[nservices] = (transport, port);
            nservices += 1;
        }
    }
    if nservices == 0 {
        return Err(Error::Service);
    }
    let config = if hints.flags & AI_ADDRCONFIG != 0 {
        backend.configuration()?
    } else {
        Configuration {
            ipv4: true,
            ipv6: true,
        }
    };
    let v4 = hints.family != AF_INET6 && config.ipv4;
    let v6 = hints.family != AF_INET && config.ipv6;
    let map4 = hints.family == AF_INET6 && hints.flags & AI_V4MAPPED != 0 && config.ipv4;
    let mut count = 0usize;
    let mut deliver = |host: Host<'_>, map: bool| -> Result<(), Error> {
        if host.address.scope != 0 && host.address.family() != AF_INET6 {
            return Err(Error::Fail);
        }
        let canonical = if hints.flags & AI_CANONNAME != 0 && node.is_some() && count == 0 {
            let name = host.canonical.or(node).ok_or(Error::Fail)?;
            if !text(name) {
                return Err(Error::Fail);
            }
            Some(name)
        } else {
            None
        };
        for (i, (transport, port)) in services[..nservices].iter().enumerate() {
            emit(Entry {
                address: if map {
                    mapped(host.address)
                } else {
                    host.address
                },
                port: *port,
                transport: *transport,
                canonical: if i == 0 { canonical } else { None },
            })?;
            count = count.checked_add(1).ok_or(Error::Overflow)?;
        }
        Ok(())
    };
    if let Some(node) = node {
        if let Some(mut address) = numeric(backend, node)? {
            // Linux-compatible application boundary: a mapped literal also
            // denotes its embedded IPv4 endpoint when AF_INET is requested.
            if hints.family == AF_INET && address.scope == 0 {
                if let Address::V6(bytes) = address.address {
                    if bytes[..10] == [0; 10] && bytes[10..12] == [255; 2] {
                        address = Address::V4(bytes[12..].try_into().unwrap()).into();
                    }
                }
            }
            let family = address.family();
            if (family == AF_INET && !v4 && !map4) || (family == AF_INET6 && !v6) {
                return Err(Error::NoName);
            }
            deliver(
                Host {
                    address,
                    canonical: None,
                },
                family == AF_INET && map4,
            )?;
        } else {
            if hints.flags & AI_NUMERICHOST != 0 {
                return Err(Error::NoName);
            }
            let mut failure = Error::NoName;
            let mut found6 = false;
            for family in [AF_INET6, AF_INET] {
                if family == AF_INET6 && !v6 {
                    continue;
                }
                if family == AF_INET && !(v4 || (map4 && (!found6 || hints.flags & AI_ALL != 0))) {
                    continue;
                }
                let mut callback_error = None;
                let mut received = false;
                let result = backend.host(node, family, &mut |host| {
                    if let Some(error) = callback_error {
                        return Err(error);
                    }
                    let result = if host.address.family() != family {
                        Err(Error::Fail)
                    } else {
                        deliver(host, family == AF_INET && map4)
                    };
                    if let Err(error) = result {
                        callback_error = Some(error);
                    } else {
                        received = true;
                    }
                    result
                });
                if let Some(error) = callback_error {
                    return Err(error);
                }
                // A failed family must not turn an emitted, incomplete prefix
                // into successful resolution. The owner discards that prefix.
                if received {
                    result?;
                }
                if family == AF_INET6 {
                    found6 = received;
                }
                match result {
                    Ok(()) | Err(Error::NoName) => {}
                    Err(Error::Again) => failure = Error::Again,
                    Err(Error::Fail) if failure != Error::Again => failure = Error::Fail,
                    Err(Error::Fail) => {}
                    Err(error) => return Err(error),
                }
            }
            drop(deliver);
            return if count != 0 { Ok(count) } else { Err(failure) };
        }
    } else {
        let passive = hints.flags & AI_PASSIVE != 0;
        if v6 {
            let mut address = [0; 16];
            if !passive {
                address[15] = 1;
            }
            deliver(
                Host {
                    address: Address::V6(address).into(),
                    canonical: None,
                },
                false,
            )?;
        }
        if v4 {
            deliver(
                Host {
                    address: Address::V4(if passive { [0; 4] } else { [127, 0, 0, 1] }).into(),
                    canonical: None,
                },
                false,
            )?;
        }
    }
    drop(deliver);
    if count == 0 {
        Err(Error::NoName)
    } else {
        Ok(count)
    }
}

fn copied(source: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if !text(source) {
        return Err(Error::Fail);
    }
    out.get_mut(..source.len())
        .ok_or(Error::Overflow)?
        .copy_from_slice(source);
    Ok(source.len())
}
fn reverse_address(address: ScopedAddress) -> ScopedAddress {
    if let Address::V6(v6) = address.address {
        if v6[..10] == [0; 10]
            && (v6[10..12] == [255, 255]
                || (v6[10..12] == [0; 2] && v6[12..] != [0, 0, 0, 0] && v6[12..] != [0, 0, 0, 1]))
        {
            return Address::V4(v6[12..].try_into().unwrap()).into();
        }
    }
    address
}

/// Buffers include their NUL terminator. None omits that output entirely.
/// Errors may leave a prefix; callers publishing to C should use private buffers.
pub fn getnameinfo<B: Backend>(
    backend: &mut B,
    address: ScopedAddress,
    port: u16,
    flags: i32,
    host: Option<&mut [u8]>,
    service: Option<&mut [u8]>,
) -> Result<(), Error> {
    if flags & !NI_FLAGS != 0 {
        return Err(Error::BadFlags);
    }
    if host.is_none() && service.is_none() {
        return Err(Error::NoName);
    }
    if address.family() != AF_INET6 && address.scope != 0 {
        return Err(Error::Family);
    }
    if let Some(out) = host {
        let mut scratch = [0; NI_MAXHOST];
        let length = if flags & NI_NUMERICHOST != 0 {
            address.format(&mut scratch)?
        } else {
            match absent(backend.reverse(reverse_address(address), &mut scratch))? {
                Some(found) => {
                    let name = scratch.get(..found.length).ok_or(Error::Fail)?;
                    if !text(name) {
                        return Err(Error::Fail);
                    }
                    if flags & NI_NOFQDN != 0 && found.local {
                        name.iter().position(|b| *b == b'.').unwrap_or(name.len())
                    } else {
                        name.len()
                    }
                }
                None if flags & NI_NAMEREQD != 0 => return Err(Error::NoName),
                None => address.format(&mut scratch)?,
            }
        };
        let n = copied(&scratch[..length], out)?;
        *out.get_mut(n).ok_or(Error::Overflow)? = 0;
    }
    if let Some(out) = service {
        let mut scratch = [0; NI_MAXSERV];
        let found = if flags & NI_NUMERICSERV != 0 {
            None
        } else {
            absent(backend.service_name(
                port,
                if flags & NI_DGRAM != 0 {
                    Transport::Udp
                } else {
                    Transport::Tcp
                },
                &mut scratch,
            ))?
        };
        let n = match found {
            Some(n) => {
                let name = scratch.get(..n).ok_or(Error::Fail)?;
                if !text(name) {
                    return Err(Error::Fail);
                }
                n
            }
            None => number(u32::from(port), &mut scratch)?,
        };
        copied(&scratch[..n], out)?;
        *out.get_mut(n).ok_or(Error::Overflow)? = 0;
    }
    Ok(())
}
