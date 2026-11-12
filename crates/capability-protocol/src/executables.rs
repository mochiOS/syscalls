//! Explicit signed executable selection. Text never grants package authority.
/// Versioned executable-reference request opcode.
pub const OPCODE: u32 = u32::from_le_bytes(*b"EXE1");
/// Select an own export (empty alias/name set) or external alias (name empty).
pub const SELECT: u16 = 0;
/// Acquire the captured original executable from an owned code token.
pub const ROOT: u16 = 1;
/// Acquire one canonical library path from that token's captured code graph.
pub const LIBRARY: u16 = 2;
/// Fixed zero-reserved header followed by alias and name bytes.
pub const HEADER_LEN: usize = 12;
/// Bounded by the broker's existing inline receive capacity.
pub const MAX_BYTES: usize = HEADER_LEN + 128 + 4095;
/// Borrowed selection; decoding performs syntax checks only.
pub struct Request<'a> {
    pub operation: u16,
    pub alias: &'a str,
    pub name: &'a str,
}
fn alias(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s != "."
        && s != ".."
        && !s
            .bytes()
            .any(|b| b == b'/' || b == b'\\' || b.is_ascii_control())
}
impl Request<'_> {
    /// Check operation-specific syntax, independently of native authority.
    pub fn valid(&self) -> bool {
        match self.operation {
            SELECT => {
                self.alias.is_empty() && alias(self.name)
                    || alias(self.alias) && self.name.is_empty()
            }
            ROOT => self.alias.is_empty() && self.name.is_empty(),
            LIBRARY => {
                self.alias.is_empty()
                    && self.name.starts_with('/')
                    && self.name.len() <= 4095
                    && !self
                        .name
                        .bytes()
                        .any(|b| b == b'\\' || b.is_ascii_control())
                    && self.name[1..]
                        .split('/')
                        .all(|p| !p.is_empty() && p != "." && p != ".." && p.len() <= 255)
            }
            _ => false,
        }
    }
    /// Encode exact lengths, rejecting ambiguity, traversal and reserved flags.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, ()> {
        let n = HEADER_LEN + self.alias.len() + self.name.len();
        if !self.valid() || out.len() < n {
            return Err(());
        }
        out[..4].copy_from_slice(&OPCODE.to_le_bytes());
        out[4..6].copy_from_slice(&self.operation.to_le_bytes());
        out[6..8].fill(0);
        out[8..10].copy_from_slice(&(self.alias.len() as u16).to_le_bytes());
        out[10..12].copy_from_slice(&(self.name.len() as u16).to_le_bytes());
        out[12..12 + self.alias.len()].copy_from_slice(self.alias.as_bytes());
        out[12 + self.alias.len()..n].copy_from_slice(self.name.as_bytes());
        Ok(n)
    }
}
/// Decode an exact, bounded request; reject trailing bytes and unknown flags.
pub fn decode(bytes: &[u8]) -> Result<Request<'_>, ()> {
    if bytes.len() < HEADER_LEN
        || bytes.len() > MAX_BYTES
        || bytes[..4] != OPCODE.to_le_bytes()
        || bytes[6..8] != [0; 2]
    {
        return Err(());
    }
    let a = u16::from_le_bytes([bytes[8], bytes[9]]) as usize;
    let n = u16::from_le_bytes([bytes[10], bytes[11]]) as usize;
    if HEADER_LEN + a + n != bytes.len() {
        return Err(());
    }
    let result = Request {
        operation: u16::from_le_bytes([bytes[4], bytes[5]]),
        alias: core::str::from_utf8(&bytes[12..12 + a]).map_err(|_| ())?,
        name: core::str::from_utf8(&bytes[12 + a..]).map_err(|_| ())?,
    };
    if !result.valid() {
        return Err(());
    }
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_operation_shapes() {
        for (operation, a, n) in [
            (SELECT, "", "helper"),
            (SELECT, "engine-helper", ""),
            (ROOT, "", ""),
            (LIBRARY, "", "/libraries/libx.so"),
        ] {
            let mut bytes = [0; MAX_BYTES];
            let k = Request {
                operation,
                alias: a,
                name: n,
            }
            .encode(&mut bytes)
            .unwrap();
            let r = decode(&bytes[..k]).unwrap();
            assert_eq!(r.alias, a);
            assert_eq!(r.name, n);
            assert!(decode(&bytes[..k + 1]).is_err());
            bytes[6] = 1;
            assert!(decode(&bytes[..k]).is_err());
        }
    }
    #[test]
    fn rejects_paths_as_selectors_and_library_escapes() {
        for (operation, a, n) in [
            (SELECT, "/engine", ""),
            (SELECT, "alias", "helper"),
            (SELECT, "", ".."),
            (ROOT, "a", ""),
            (LIBRARY, "", "/libraries/../x"),
            (LIBRARY, "", "/libraries//x"),
            (LIBRARY, "", "relative"),
            (3, "", ""),
        ] {
            assert!(
                !Request {
                    operation,
                    alias: a,
                    name: n
                }
                .valid()
            );
        }
    }
}
