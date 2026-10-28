//! Validate lifecycle metadata against the captured object's LOAD segments.
//! Array elements are function pointers after relocation, not raw file values.
use super::{Error, Pie, add, extent, u64_at};

#[derive(Clone, Copy, Default)]
pub(super) struct Array {
    pub address: u64,
    pub count: u64,
}

#[derive(Clone, Copy, Default)]
pub(super) struct Metadata {
    pub init: u64,
    pub fini: u64,
    pub preinit: Array,
    pub initialize: Array,
    pub finalize: Array,
}
impl Metadata {
    pub fn parse(image: &Pie<'_>) -> Result<Self, Error> {
        let mut values = [None; 8];
        if let Some(dynamic) = image.dynamic_segment {
            for offset in extent(image.bytes, dynamic.offset, dynamic.file)?.step_by(16) {
                let tag = u64_at(image.bytes, offset)?;
                if tag == 0 {
                    break;
                }
                let slot = match tag {
                    12 => 0,
                    13 => 1,
                    32 => 2,
                    33 => 3,
                    25 => 4,
                    27 => 5,
                    26 => 6,
                    28 => 7,
                    _ => continue,
                };
                if values[slot]
                    .replace(u64_at(image.bytes, offset + 8)?)
                    .is_some()
                {
                    return Err(Error::Invalid);
                }
            }
        }
        let function = |value: Option<u64>| {
            let address = value.unwrap_or(0);
            if address != 0
                && !(0..image.count).any(|index| {
                    image
                        .segment(index)
                        .is_ok_and(|segment| segment.flags & 1 != 0 && segment.contains(address, 1))
                })
            {
                return Err(Error::Invalid);
            }
            Ok(address)
        };
        let array = |address: Option<u64>, bytes: Option<u64>| {
            let (address, bytes) = match (address, bytes) {
                (None, None) => return Ok(Array::default()),
                (Some(address), Some(bytes)) => (address, bytes),
                _ => return Err(Error::Invalid),
            };
            if bytes % 8 != 0 || address % 8 != 0 {
                return Err(Error::Invalid);
            }
            add(address, bytes)?;
            if bytes != 0
                && !(0..image.count).any(|index| {
                    image.segment(index).is_ok_and(|segment| {
                        segment.flags & 4 != 0 && segment.contains(address, bytes)
                    })
                })
            {
                return Err(Error::Invalid);
            }
            Ok(Array {
                address,
                count: bytes / 8,
            })
        };
        Ok(Self {
            init: function(values[0])?,
            fini: function(values[1])?,
            preinit: array(values[2], values[3])?,
            initialize: array(values[4], values[5])?,
            finalize: array(values[6], values[7])?,
        })
    }

    pub fn has_calls(self) -> bool {
        self.init != 0
            || self.fini != 0
            || self.preinit.count != 0
            || self.initialize.count != 0
            || self.finalize.count != 0
    }
}
