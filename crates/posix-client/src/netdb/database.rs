//! Borrowed hosts/services records. The owner loads an authorized file; no
//! pathname or ambient filesystem access is hidden in these parsers.
use super::{AF_INET, AF_INET6, Address, Transport};

fn words(line: &[u8]) -> impl Iterator<Item = &[u8]> {
    let end = line.iter().position(|b| *b == b'#').unwrap_or(line.len());
    line[..end]
        .split(u8::is_ascii_whitespace)
        .filter(|w| !w.is_empty())
}
#[derive(Clone, Copy, Debug)]
pub struct Host<'a> {
    pub address: Address,
    pub canonical: &'a [u8],
    line: &'a [u8],
}
impl Host<'_> {
    pub fn matches(&self, name: &[u8]) -> bool {
        words(self.line)
            .skip(1)
            .any(|alias| alias.eq_ignore_ascii_case(name))
    }
}
pub fn hosts(data: &[u8]) -> impl Iterator<Item = Host<'_>> {
    data.split(|b| *b == b'\n').filter_map(|line| {
        let mut parts = words(line);
        let ip = parts.next()?;
        let canonical = parts.next()?;
        if line.contains(&0) {
            return None;
        }
        let address = Address::parse(AF_INET, ip)
            .ok()
            .flatten()
            .or_else(|| Address::parse(AF_INET6, ip).ok().flatten())?;
        Some(Host {
            address,
            canonical,
            line,
        })
    })
}
#[derive(Clone, Copy, Debug)]
pub struct Service<'a> {
    pub name: &'a [u8],
    pub port: u16,
    pub transport: Transport,
    line: &'a [u8],
}
impl Service<'_> {
    pub fn matches(&self, name: &[u8]) -> bool {
        self.name == name || words(self.line).skip(2).any(|alias| alias == name)
    }
}
pub fn services(data: &[u8]) -> impl Iterator<Item = Service<'_>> {
    data.split(|b| *b == b'\n').filter_map(|line| {
        let mut parts = words(line);
        let name = parts.next()?;
        let spec = parts.next()?;
        if line.contains(&0) {
            return None;
        }
        let slash = spec.iter().position(|b| *b == b'/')?;
        let port = super::decimal(&spec[..slash]).and_then(|n| u16::try_from(n).ok())?;
        let transport = match &spec[slash + 1..] {
            b"tcp" => Transport::Tcp,
            b"udp" => Transport::Udp,
            _ => return None,
        };
        Some(Service {
            name,
            port,
            transport,
            line,
        })
    })
}
