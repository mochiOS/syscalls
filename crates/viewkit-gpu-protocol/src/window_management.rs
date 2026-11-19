//! Privileged window-manager messages. These describe window geometry, never
//! application identities, shell modes or permission to access other surfaces.

pub const SNAPSHOT: u32 = 112;
pub const PRESENT: u32 = 113;
pub const CLOSE: u32 = 114;
pub const SET_DEFERRED_INPUT: u32 = 115;
pub const PREVIEW: u32 = 116;
pub const VERSION: u32 = 1;
pub const MAX_WINDOWS: usize = 8;
pub const HEADER_LEN: usize = 16;
pub const RECORD_LEN: usize = 112;
pub const MAX_REPLY: usize = HEADER_LEN + MAX_WINDOWS * RECORD_LEN;
pub const TITLE_BYTES: usize = 64;
pub const PREVIEW_MAX_SIDE: u32 = 120;
pub const PREVIEW_MAX_BYTES: usize =
    HEADER_LEN + PREVIEW_MAX_SIDE as usize * PREVIEW_MAX_SIDE as usize * 4;

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

/// A panel can defer primary input in this region until the pointer moves
/// beyond the physical-pixel slop. An empty region disables deferral.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeferredInput {
    pub bounds: Bounds,
    pub slop: u32,
}

impl DeferredInput {
    pub fn encode(self) -> [u8; 24] {
        let mut bytes = [0; 24];
        put(&mut bytes, 0, SET_DEFERRED_INPUT);
        put(&mut bytes, 4, self.slop);
        put_bounds(&mut bytes, 8, self.bounds);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 24 || get(bytes, 0)? != SET_DEFERRED_INPUT {
            return None;
        }
        let bounds = bounds(bytes, 8)?;
        let slop = get(bytes, 4)?;
        if slop > 64 || (slop > 0 && (bounds.width == 0 || bounds.height == 0)) {
            return None;
        }
        Some(Self { bounds, slop })
    }
}

pub fn preview_request(window: u64) -> [u8; 12] {
    let mut request = [0; 12];
    put(&mut request, 0, PREVIEW);
    request[4..].copy_from_slice(&window.to_le_bytes());
    request
}

pub fn preview_header(header: &mut [u8], width: u32, height: u32) -> Option<()> {
    if header.len() != HEADER_LEN || preview_pixel_len(width, height).is_none() {
        return None;
    }
    header.fill(0);
    put(header, 4, VERSION);
    put(header, 8, width);
    put(header, 12, height);
    Some(())
}

pub fn preview_image(bytes: &[u8]) -> Option<(u32, u32, &[u8])> {
    if get(bytes, 0)? != 0 || get(bytes, 4)? != VERSION {
        return None;
    }
    let width = get(bytes, 8)?;
    let height = get(bytes, 12)?;
    let pixels = bytes.get(HEADER_LEN..)?;
    (pixels.len() == preview_pixel_len(width, height)?).then_some((width, height, pixels))
}

fn preview_pixel_len(width: u32, height: u32) -> Option<usize> {
    let valid_side = |side| (1..=PREVIEW_MAX_SIDE).contains(&side);
    (valid_side(width) && valid_side(height)).then(|| width as usize * height as usize * 4)
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
    fn deferred_input_and_preview_reject_invalid_lengths() {
        let region = DeferredInput {
            bounds: Bounds {
                x: 0,
                y: 700,
                width: 1024,
                height: 44,
            },
            slop: 10,
        };
        assert_eq!(DeferredInput::decode(&region.encode()), Some(region));
        assert_eq!(DeferredInput::decode(&region.encode()[..20]), None);
        assert!(DeferredInput::decode(&DeferredInput { slop: 65, ..region }.encode()).is_none());
        let mut bytes = [0; HEADER_LEN + 4];
        preview_header(&mut bytes[..HEADER_LEN], 1, 1).unwrap();
        assert_eq!(preview_image(&bytes), Some((1, 1, &[0; 4][..])));
        assert!(preview_image(&bytes[..HEADER_LEN]).is_none());
        assert!(preview_header(&mut bytes[..HEADER_LEN], PREVIEW_MAX_SIDE + 1, 1).is_none());
    }
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
