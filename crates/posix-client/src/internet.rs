//! Value-only Internet address conversion. No endpoint, capability lookup or
//! process state is needed for presentation/network byte-order conversion.
use core::{
    fmt::{self, Write},
    net::{Ipv4Addr, Ipv6Addr},
    str,
};

pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;
pub const INET_ADDRSTRLEN: usize = 16;
pub const INET6_ADDRSTRLEN: usize = 46;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Address {
    V4([u8; 4]),
    V6([u8; 16]),
}
pub fn address_length(family: i32) -> Result<usize, i32> {
    match family {
        AF_INET => Ok(4),
        AF_INET6 => Ok(16),
        _ => Err(-97),
    }
}
impl Address {
    /// The slice is the complete presentation, without a C string terminator.
    /// Invalid syntax is distinct from an unsupported address family.
    pub fn parse(family: i32, text: &[u8]) -> Result<Option<Self>, i32> {
        address_length(family)?;
        let Ok(text) = str::from_utf8(text) else {
            return Ok(None);
        };
        Ok(match family {
            AF_INET => text.parse::<Ipv4Addr>().ok().map(|a| Self::V4(a.octets())),
            AF_INET6 => text.parse::<Ipv6Addr>().ok().map(|a| Self::V6(a.octets())),
            _ => return Err(-97),
        })
    }
    pub fn from_octets(family: i32, bytes: &[u8]) -> Result<Self, i32> {
        match family {
            AF_INET => bytes.try_into().map(Self::V4).map_err(|_| -22),
            AF_INET6 => bytes.try_into().map(Self::V6).map_err(|_| -22),
            _ => Err(-97),
        }
    }
    pub fn octets(&self) -> &[u8] {
        match self {
            Self::V4(a) => a,
            Self::V6(a) => a,
        }
    }
    /// Writes presentation bytes without a NUL; callers may use a private
    /// INET6_ADDRSTRLEN buffer before committing a bounded C output.
    pub fn format(&self, out: &mut [u8]) -> Result<usize, i32> {
        let mut buffer = Buffer {
            bytes: out,
            used: 0,
        };
        match self {
            Self::V4(a) => write!(buffer, "{}", Ipv4Addr::from(*a)),
            Self::V6(a) if a[..12] == [0; 12] && a[12..14] != [0; 2] => {
                write!(buffer, "::{}", Ipv4Addr::new(a[12], a[13], a[14], a[15]))
            }
            Self::V6(a) => write!(buffer, "{}", Ipv6Addr::from(*a)),
        }
        .map_err(|_| -28)?;
        Ok(buffer.used)
    }
}
struct Buffer<'a> {
    bytes: &'a mut [u8],
    used: usize,
}
impl Write for Buffer<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.used.checked_add(text.len()).ok_or(fmt::Error)?;
        self.bytes
            .get_mut(self.used..end)
            .ok_or(fmt::Error)?
            .copy_from_slice(text.as_bytes());
        self.used = end;
        Ok(())
    }
}
