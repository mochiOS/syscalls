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

/// Parse the historical inet_aton syntax (one to four decimal/octal/hex parts).
/// This is deliberately separate from strict inet_pton and hostname lookup:
/// callers such as GIO use it to *reject* ambiguous numeric hostnames.
/// Returns network-order octets; overflow and non-whitespace suffixes fail.
pub fn legacy_ipv4(mut text: &[u8]) -> Option<[u8; 4]> {
    while text.last().is_some_and(u8::is_ascii_whitespace) {
        text = &text[..text.len() - 1];
    }
    let mut parts = [0u32; 4];
    let mut count = 0;
    for part in text.split(|byte| *byte == b'.') {
        if part.is_empty() || count == 4 {
            return None;
        }
        let (radix, digits) = if part.starts_with(b"0x") || part.starts_with(b"0X") {
            (16u32, &part[2..])
        } else if part.len() > 1 && part[0] == b'0' {
            (8, &part[1..])
        } else {
            (10, part)
        };
        if digits.is_empty() {
            return None;
        }
        let mut value = 0u32;
        for &byte in digits {
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a' + 10),
                b'A'..=b'F' => u32::from(byte - b'A' + 10),
                _ => return None,
            };
            if digit >= radix {
                return None;
            }
            value = value.checked_mul(radix)?.checked_add(digit)?;
        }
        parts[count] = value;
        count += 1;
    }
    let mut address = 0u32;
    for part in &parts[..count - 1] {
        if *part > 255 {
            return None;
        }
        address = (address << 8) | part;
    }
    let remaining = (5 - count) * 8;
    if u64::from(parts[count - 1]) >= (1u64 << remaining) {
        return None;
    }
    Some(
        ((u64::from(address) << remaining) | u64::from(parts[count - 1])).to_be_bytes()[4..]
            .try_into()
            .unwrap(),
    )
}
