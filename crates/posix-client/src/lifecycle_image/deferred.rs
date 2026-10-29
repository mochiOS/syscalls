//! Snapshot lifecycle recipes before resolvers, then read array values after
//! relocation. Normalize to the existing flat lifecycle image before any call.
use super::{Error, Image, MAGIC, OBJECT_BYTES};
pub const VERSION: u32 = 2;
pub const HEADER_BYTES: usize = 48;
pub const REGION_BYTES: usize = 24;
pub const CALLBACK_BYTES: usize = 16;
const USER_MIN: u64 = 0x0040_0000;
const USER_END: u64 = 0x0000_8000_0000_0000;

fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// Private immutable metadata. Array element values have not yet been read.
pub struct Plan<'a> {
    bytes: &'a [u8],
    objects: usize,
    regions: usize,
    region_start: usize,
    callbacks: usize,
    calls: usize,
    flat_length: usize,
}
impl<'a> Plan<'a> {
    pub fn parse<E>(bytes: &'a [u8]) -> Result<Self, Error<E>> {
        if bytes.len() < HEADER_BYTES
            || word(bytes, 0) != MAGIC
            || word(bytes, 8) as u32 != VERSION
            || word(bytes, 40) != 0
        {
            return Err(Error::Invalid);
        }
        let objects = (word(bytes, 8) >> 32) as usize;
        let regions = usize::try_from(word(bytes, 32)).map_err(|_| Error::TooLarge)?;
        if objects == 0 || word(bytes, 16) != bytes.len() as u64 {
            return Err(Error::Invalid);
        }
        let region_start = objects
            .checked_mul(OBJECT_BYTES)
            .and_then(|n| HEADER_BYTES.checked_add(n))
            .ok_or(Error::TooLarge)?;
        let callbacks = regions
            .checked_mul(REGION_BYTES)
            .and_then(|n| region_start.checked_add(n))
            .ok_or(Error::TooLarge)?;
        if callbacks > bytes.len() || (bytes.len() - callbacks) % CALLBACK_BYTES != 0 {
            return Err(Error::Invalid);
        }
        let calls = (bytes.len() - callbacks) / CALLBACK_BYTES;
        let flat_length = objects
            .checked_mul(OBJECT_BYTES)
            .and_then(|n| super::HEADER_BYTES.checked_add(n))
            .and_then(|n| calls.checked_mul(8)?.checked_add(n))
            .ok_or(Error::TooLarge)?;
        let plan = Self {
            bytes,
            objects,
            regions,
            region_start,
            callbacks,
            calls,
            flat_length,
        };
        let mut end = USER_MIN;
        for index in 0..regions {
            let at = region_start + index * REGION_BYTES;
            let address = word(bytes, at);
            let length = word(bytes, at + 8);
            let flags = word(bytes, at + 16);
            if address < end || length == 0 || flags & !7 != 0 || flags & 3 == 3 {
                return Err(Error::Invalid);
            }
            end = address
                .checked_add(length)
                .filter(|end| *end <= USER_END)
                .ok_or(Error::Invalid)?;
        }
        let count = |value| usize::try_from(value).map_err(|_| Error::TooLarge);
        let mut cursor = count(word(bytes, 24))?
            .checked_mul(CALLBACK_BYTES)
            .and_then(|n| callbacks.checked_add(n))
            .filter(|end| *end <= bytes.len())
            .ok_or(Error::Invalid)?;
        for index in 0..objects {
            let descriptor = HEADER_BYTES + index * OBJECT_BYTES;
            for at in [descriptor, descriptor + 16] {
                if word(bytes, at) != cursor as u64 {
                    return Err(Error::Invalid);
                }
                cursor = count(word(bytes, at + 8))?
                    .checked_mul(CALLBACK_BYTES)
                    .and_then(|n| cursor.checked_add(n))
                    .filter(|end| *end <= bytes.len())
                    .ok_or(Error::Invalid)?;
            }
        }
        if cursor != bytes.len() {
            return Err(Error::Invalid);
        }
        // Validate the entire recipe, including every array's source extent,
        // without touching any of its not-yet-relocated pointer values.
        for at in (callbacks..bytes.len()).step_by(CALLBACK_BYTES) {
            let address = word(bytes, at + 8);
            let valid = match word(bytes, at) {
                0 => plan.contains(address, 1, 1),
                1 => address % 8 == 0 && plan.contains(address, 8, 4),
                _ => false,
            };
            if !valid {
                return Err(Error::Invalid);
            }
        }
        Ok(plan)
    }
    fn contains(&self, address: u64, length: u64, flag: u64) -> bool {
        let (mut low, mut high) = (0, self.regions);
        while low < high {
            let mid = low + (high - low) / 2;
            if word(self.bytes, self.region_start + mid * REGION_BYTES) <= address {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        if low == 0 {
            return false;
        }
        let at = self.region_start + (low - 1) * REGION_BYTES;
        word(self.bytes, at + 16) & flag != 0
            && address
                .checked_add(length)
                .is_some_and(|end| end <= word(self.bytes, at) + word(self.bytes, at + 8))
    }
    pub fn flat_length(&self) -> usize {
        self.flat_length
    }

    /// Run only after deferred relocations. All resolved callback addresses
    /// are checked and privately stored before a caller may invoke even one.
    /// Discard output on error. This never calls code or changes permissions.
    pub fn resolve<E>(
        &self,
        output: &mut [u8],
        mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
    ) -> Result<usize, Error<E>> {
        if output.len() < self.flat_length {
            return Err(Error::TooLarge);
        }
        let output = &mut output[..self.flat_length];
        output.fill(0);
        put(output, 0, MAGIC);
        put(
            output,
            8,
            u64::from(super::VERSION) | ((self.objects as u64) << 32),
        );
        put(output, 16, self.flat_length as u64);
        put(output, 24, word(self.bytes, 24));
        let start = super::HEADER_BYTES + self.objects * OBJECT_BYTES;
        for index in 0..self.objects {
            let from = HEADER_BYTES + index * OBJECT_BYTES;
            let to = super::HEADER_BYTES + index * OBJECT_BYTES;
            for delta in [0, 16] {
                let ordinal =
                    (word(self.bytes, from + delta) as usize - self.callbacks) / CALLBACK_BYTES;
                put(output, to + delta, (start + ordinal * 8) as u64);
                put(output, to + delta + 8, word(self.bytes, from + delta + 8));
            }
        }
        for index in 0..self.calls {
            let at = self.callbacks + index * CALLBACK_BYTES;
            let source = word(self.bytes, at + 8);
            let address = if word(self.bytes, at) == 1 {
                let mut bytes = [0; 8];
                read(source, &mut bytes).map_err(Error::Read)?;
                u64::from_le_bytes(bytes)
            } else {
                source
            };
            if !self.contains(address, 1, 1) {
                return Err(Error::Invalid);
            }
            put(output, start + index * 8, address);
        }
        Ok(self.flat_length)
    }
}

/// Allocation preflight only; capture repeats every header and bounds check
/// before copying the complete metadata into the supplied private storage.
pub fn encoded_length<E>(
    base: u64,
    maximum: usize,
    mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<usize, Error<E>> {
    if base < USER_MIN
        || base % 8 != 0
        || maximum < super::HEADER_BYTES
        || base
            .checked_add(super::HEADER_BYTES as u64)
            .is_none_or(|n| n > USER_END)
    {
        return Err(Error::Invalid);
    }
    let mut header = [0; super::HEADER_BYTES];
    read(base, &mut header).map_err(Error::Read)?;
    if word(&header, 0) != MAGIC || !matches!(word(&header, 8) as u32, super::VERSION | VERSION) {
        return Err(Error::Invalid);
    }
    let length = usize::try_from(word(&header, 16)).map_err(|_| Error::TooLarge)?;
    if length > maximum {
        return Err(Error::TooLarge);
    }
    if length < super::HEADER_BYTES || base.checked_add(length as u64).is_none_or(|n| n > USER_END)
    {
        return Err(Error::Invalid);
    }
    Ok(length)
}
/// Copy the complete metadata before resolvers or constructors. The common
/// header is read once, so changing its length later cannot enlarge capture.
/// Version 2 validation reads recipes only, never final array element values.
pub fn capture<E>(
    base: u64,
    maximum: usize,
    output: &mut [u8],
    mut read: impl FnMut(u64, &mut [u8]) -> Result<(), E>,
) -> Result<usize, Error<E>> {
    if base < USER_MIN || base % 8 != 0 || maximum < super::HEADER_BYTES {
        return Err(Error::Invalid);
    }
    base.checked_add(super::HEADER_BYTES as u64)
        .filter(|end| *end <= USER_END)
        .ok_or(Error::Invalid)?;
    let mut header = [0; super::HEADER_BYTES];
    read(base, &mut header).map_err(Error::Read)?;
    let version = word(&header, 8) as u32;
    if word(&header, 0) != MAGIC || !matches!(version, super::VERSION | VERSION) {
        return Err(Error::Invalid);
    }
    let length = usize::try_from(word(&header, 16)).map_err(|_| Error::TooLarge)?;
    if length > maximum || length > output.len() {
        return Err(Error::TooLarge);
    }
    if length < super::HEADER_BYTES
        || base
            .checked_add(length as u64)
            .is_none_or(|end| end > USER_END)
    {
        return Err(Error::Invalid);
    }
    let output = &mut output[..length];
    output[..header.len()].copy_from_slice(&header);
    read(base + header.len() as u64, &mut output[header.len()..]).map_err(Error::Read)?;
    if version == VERSION {
        Plan::parse::<E>(output)?;
    } else {
        Image::read(base, length, |address, bytes| -> Result<(), E> {
            // Image's validated offsets are confined to this captured slice.
            let at = (address - base) as usize;
            bytes.copy_from_slice(&output[at..at + bytes.len()]);
            Ok(())
        })?;
    }
    Ok(length)
}
