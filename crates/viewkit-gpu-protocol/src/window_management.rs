//! Privileged window-manager messages. These describe window geometry, never
//! application identities, shell modes or permission to access other surfaces.

pub const SNAPSHOT: u32 = 112;
pub const PRESENT: u32 = 113;
pub const CLOSE: u32 = 114;
pub const VERSION: u32 = 1;
pub const MAX_WINDOWS: usize = 8;
pub const HEADER_LEN: usize = 16;
pub const RECORD_LEN: usize = 112;
pub const MAX_REPLY: usize = HEADER_LEN + MAX_WINDOWS * RECORD_LEN;
pub const TITLE_BYTES: usize = 64;

pub const MINIMIZED: u32 = 1;
pub const FOCUSED: u32 = 2;
pub const RESIZABLE: u32 = 4;
pub const PROTECTED: u32 = 8;
pub const MANAGED: u32 = 16;

pub const LEASE: u32 = 1;
pub const VISIBLE: u32 = 2;
pub const ACTIVATE: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Present {
    pub window: u64,
    pub flags: u32,
    pub bounds: Bounds,
}

impl Present {
    pub fn encode(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        put(&mut bytes, 0, PRESENT);
        bytes[4..12].copy_from_slice(&self.window.to_le_bytes());
        put(&mut bytes, 12, self.flags);
        put_bounds(&mut bytes, 16, self.bounds);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 || get(bytes, 0)? != PRESENT {
            return None;
        }
        let flags = get(bytes, 12)?;
        if flags & !(LEASE | VISIBLE | ACTIVATE) != 0
            || (flags & ACTIVATE != 0 && flags & VISIBLE == 0)
            || (flags & LEASE == 0 && flags != 0)
        {
            return None;
        }
        let value = Self {
            window: get64(bytes, 4)?,
            flags,
            bounds: bounds(bytes, 16)?,
        };
        (value.window != 0 && (flags == 0 || (value.bounds.width > 0 && value.bounds.height > 0)))
            .then_some(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowInfo<'a> {
    pub token: u64,
    pub process: u64,
    pub bounds: Bounds,
    pub flags: u32,
    pub title: &'a str,
}

impl WindowInfo<'_> {
    pub fn encode(self, bytes: &mut [u8]) -> Option<()> {
        if bytes.len() != RECORD_LEN || self.title.len() > TITLE_BYTES {
            return None;
        }
        bytes.fill(0);
        bytes[..8].copy_from_slice(&self.token.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.process.to_le_bytes());
        put_bounds(bytes, 16, self.bounds);
        put(bytes, 32, self.flags);
        put(bytes, 36, self.title.len() as u32);
        bytes[40..40 + self.title.len()].copy_from_slice(self.title.as_bytes());
        Some(())
    }
}

impl<'a> WindowInfo<'a> {
    pub fn decode(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() != RECORD_LEN || bytes[104..].iter().any(|&byte| byte != 0) {
            return None;
        }
        let title_len = get(bytes, 36)? as usize;
        let flags = get(bytes, 32)?;
        if title_len > TITLE_BYTES
            || flags & !(MINIMIZED | FOCUSED | RESIZABLE | PROTECTED | MANAGED) != 0
        {
            return None;
        }
        let value = Self {
            token: get64(bytes, 0)?,
            process: get64(bytes, 8)?,
            bounds: bounds(bytes, 16)?,
            flags,
            title: core::str::from_utf8(&bytes[40..40 + title_len]).ok()?,
        };
        (value.token != 0
            && value.process != 0
            && value.bounds.width != 0
            && value.bounds.height != 0)
            .then_some(value)
    }
}

pub fn snapshot_header(bytes: &mut [u8], count: usize) -> Option<()> {
    if count > MAX_WINDOWS || bytes.len() != HEADER_LEN + count * RECORD_LEN {
        return None;
    }
    bytes[..HEADER_LEN].fill(0);
    put(bytes, 4, VERSION);
    put(bytes, 8, count as u32);
    put(bytes, 12, RECORD_LEN as u32);
    Some(())
}

pub fn snapshot_records(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < HEADER_LEN
        || get(bytes, 0)? != 0
        || get(bytes, 4)? != VERSION
        || get(bytes, 12)? as usize != RECORD_LEN
    {
        return None;
    }
    let count = get(bytes, 8)? as usize;
    (count <= MAX_WINDOWS && bytes.len() == HEADER_LEN + count * RECORD_LEN)
        .then_some(&bytes[HEADER_LEN..])
}

fn bounds(bytes: &[u8], at: usize) -> Option<Bounds> {
    Some(Bounds {
        x: get(bytes, at)? as i32,
        y: get(bytes, at + 4)? as i32,
        width: get(bytes, at + 8)?,
        height: get(bytes, at + 12)?,
    })
}
fn put_bounds(bytes: &mut [u8], at: usize, value: Bounds) {
    put(bytes, at, value.x as u32);
    put(bytes, at + 4, value.y as u32);
    put(bytes, at + 8, value.width);
    put(bytes, at + 12, value.height);
}
fn get(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}
fn get64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}
fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_snapshot_preserves_window_identity_and_rejects_truncation() {
        let value = WindowInfo {
            token: 17,
            process: 23,
            bounds: Bounds {
                x: 0,
                y: 34,
                width: 1280,
                height: 766,
            },
            flags: FOCUSED,
            title: "文書",
        };
        let mut bytes = [0; HEADER_LEN + RECORD_LEN];
        snapshot_header(&mut bytes, 1).unwrap();
        value.encode(&mut bytes[HEADER_LEN..]).unwrap();
        assert_eq!(
            WindowInfo::decode(snapshot_records(&bytes).unwrap()),
            Some(value)
        );
        assert!(snapshot_records(&bytes[..bytes.len() - 1]).is_none());
        bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(snapshot_records(&bytes).is_none());
    }
    #[test]
    fn presentation_cannot_encode_activation_of_a_hidden_or_unleased_window() {
        let value = Present {
            window: 7,
            flags: LEASE | VISIBLE | ACTIVATE,
            bounds: Bounds {
                x: 0,
                y: 34,
                width: 1280,
                height: 766,
            },
        };
        assert_eq!(Present::decode(&value.encode()), Some(value));
        assert!(
            Present::decode(
                &Present {
                    flags: LEASE | ACTIVATE,
                    ..value
                }
                .encode()
            )
            .is_none()
        );
        assert!(
            Present::decode(
                &Present {
                    flags: VISIBLE,
                    ..value
                }
                .encode()
            )
            .is_none()
        );
    }
}
