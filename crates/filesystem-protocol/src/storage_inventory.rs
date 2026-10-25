//! Read-only, paginated observations of storage owned by filesystem.service.
//! Dispatch requires a READ Handle to the namespace root, not an inline object ID.
pub const GET: u64 = u64::from_le_bytes(*b"MFS1INVT");
pub const RECORD_LEN: usize = 320;
pub const MAX_RECORDS: usize = 4096;
pub const DISK: u8 = 1;
pub const PARTITION: u8 = 2;
pub const VOLUME: u8 = 3;
pub const OUTSIDE_PARTITIONS: u8 = 4;
pub const READ_ONLY: u32 = 1;
pub const ACCESS_KNOWN: u32 = 2;
pub const USAGE_KNOWN: u32 = 4;
pub const CAPACITY_FROM_PARTITION_MAP: u32 = 8;
const FLAGS: u32 = READ_ONLY | ACCESS_KNOWN | USAGE_KNOWN | CAPACITY_FROM_PARTITION_MAP;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub generation: u64,
    pub index: u64,
}
impl Request {
    pub fn encode(self) -> [u8; 16] {
        let mut out = [0; 16];
        out[..8].copy_from_slice(&self.generation.to_le_bytes());
        out[8..].copy_from_slice(&self.index.to_le_bytes());
        out
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; 16] = bytes.try_into().ok()?;
        let result = Self {
            generation: u64::from_le_bytes(bytes[..8].try_into().ok()?),
            index: u64::from_le_bytes(bytes[8..].try_into().ok()?),
        };
        (result.index <= MAX_RECORDS as u64 && (result.generation != 0 || result.index == 0))
            .then_some(result)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub generation: u64,
    pub warning: u32,
    pub kind: u8,
    pub id: u64,
    pub parent: u64,
    pub capacity: u64,
    pub used: u64,
    pub flags: u32,
    pub start: u64,
    pub sector_bytes: u32,
    pub name: &'a str,
    pub format: &'a str,
    pub mount: &'a str,
}
impl<'a> Record<'a> {
    pub fn end(generation: u64, warning: u32) -> Self {
        Self {
            generation,
            warning,
            kind: 0,
            id: 0,
            parent: 0,
            capacity: 0,
            used: 0,
            flags: 0,
            start: 0,
            sector_bytes: 0,
            name: "",
            format: "",
            mount: "",
        }
    }
    pub fn encode(self) -> Option<[u8; RECORD_LEN]> {
        if !self.valid() {
            return None;
        }
        let mut out = [0; RECORD_LEN];
        out[..4].copy_from_slice(b"MSI1");
        out[4..6].copy_from_slice(&1u16.to_le_bytes());
        out[6] = self.kind;
        for (offset, value) in [
            (8, self.generation),
            (16, self.id),
            (24, self.parent),
            (32, self.capacity),
            (40, self.used),
            (56, self.start),
        ] {
            out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        out[48..52].copy_from_slice(&self.flags.to_le_bytes());
        out[52..56].copy_from_slice(&self.warning.to_le_bytes());
        out[64..68].copy_from_slice(&self.sector_bytes.to_le_bytes());
        for (offset, len_offset, text) in [
            (80, 68, self.name),
            (144, 70, self.format),
            (160, 72, self.mount),
        ] {
            out[len_offset..len_offset + 2].copy_from_slice(&(text.len() as u16).to_le_bytes());
            out[offset..offset + text.len()].copy_from_slice(text.as_bytes());
        }
        Some(out)
    }
    pub fn decode(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() != RECORD_LEN
            || &bytes[..4] != b"MSI1"
            || bytes[4..6] != 1u16.to_le_bytes()
            || bytes[7] != 0
            || bytes[74..80] != [0; 6]
        {
            return None;
        }
        let u64_at = |i| Some(u64::from_le_bytes(bytes.get(i..i + 8)?.try_into().ok()?));
        let u32_at = |i| Some(u32::from_le_bytes(bytes.get(i..i + 4)?.try_into().ok()?));
        let text = |i, l, max| {
            let len = u16::from_le_bytes(bytes.get(l..l + 2)?.try_into().ok()?) as usize;
            if len > max || bytes.get(i + len..i + max)?.iter().any(|b| *b != 0) {
                return None;
            }
            core::str::from_utf8(bytes.get(i..i + len)?).ok()
        };
        let result = Self {
            generation: u64_at(8)?,
            warning: u32_at(52)?,
            kind: bytes[6],
            id: u64_at(16)?,
            parent: u64_at(24)?,
            capacity: u64_at(32)?,
            used: u64_at(40)?,
            flags: u32_at(48)?,
            start: u64_at(56)?,
            sector_bytes: u32_at(64)?,
            name: text(80, 68, 64)?,
            format: text(144, 70, 16)?,
            mount: text(160, 72, 160)?,
        };
        result.valid().then_some(result)
    }
    fn valid(&self) -> bool {
        if self.kind == 0 {
            return self.generation != 0
                && self.warning <= i32::MAX as u32
                && *self == Self::end(self.generation, self.warning);
        }
        if self.flags & CAPACITY_FROM_PARTITION_MAP != 0 && self.kind != DISK
            || self.flags & USAGE_KNOWN != 0 && self.kind != VOLUME
        {
            return false;
        }
        self.generation != 0
            && self.warning <= i32::MAX as u32
            && self.kind <= OUTSIDE_PARTITIONS
            && self.flags & !FLAGS == 0
            && (self.flags & READ_ONLY == 0 || self.flags & ACCESS_KNOWN != 0)
            && (self.flags & USAGE_KNOWN == 0 && self.used == 0
                || self.flags & USAGE_KNOWN != 0 && self.used <= self.capacity)
            && self.name.len() <= 64
            && self.format.len() <= 16
            && self.mount.len() <= 160
            && !self.name.contains('\0')
            && !self.format.contains('\0')
            && !self.mount.contains('\0')
            && (self.kind == 0 && self.id == 0 && self.parent == 0 && self.name.is_empty()
                || self.kind != 0
                    && self.id != 0
                    && self.id != self.parent
                    && !self.name.is_empty())
            && (self.mount.is_empty() || self.kind == VOLUME && self.mount.starts_with('/'))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_reject_invalid_records() {
        let record = Record {
            kind: VOLUME,
            id: 42,
            capacity: 100,
            used: 30,
            flags: USAGE_KNOWN,
            name: "Data",
            format: "ext4",
            mount: "/",
            ..Record::end(9, 0)
        };
        let bytes = record.encode().unwrap();
        assert_eq!(Record::decode(&bytes), Some(record));
        for i in [0, 4, 7, 74, 145, 319] {
            let mut bad = bytes;
            bad[i] ^= 128;
            assert!(Record::decode(&bad).is_none());
        }
        assert!(
            Record {
                used: 101,
                ..record
            }
            .encode()
            .is_none()
        );
        assert!(
            Record {
                parent: 42,
                ..record
            }
            .encode()
            .is_none()
        );
        assert!(Record::decode(&bytes[..319]).is_none());
    }
    #[test]
    fn requests_are_bounded_and_require_a_snapshot_after_the_first_page() {
        assert!(
            Request::decode(
                &Request {
                    generation: 0,
                    index: 1
                }
                .encode()
            )
            .is_none()
        );
        assert!(
            Request::decode(
                &Request {
                    generation: 1,
                    index: MAX_RECORDS as u64 + 1
                }
                .encode()
            )
            .is_none()
        );
        assert_eq!(
            Request::decode(
                &Request {
                    generation: 0,
                    index: 0
                }
                .encode()
            ),
            Some(Request {
                generation: 0,
                index: 0
            })
        );
    }
}
