//! A bounded view of a provider after relocation, without materializing an
//! additional ELF or reading live process memory. Providers cannot contain COPY.
use super::{Error, LOAD, Pie, Value, add, extent};

impl Pie<'_> {
    pub(super) fn has_copies(&self) -> Result<bool, Error> {
        let mut copies = false;
        self.relocations(|_, value| {
            copies |= matches!(value, Value::Copy { .. });
            Ok(())
        })?;
        Ok(copies)
    }

    pub(super) fn read_relocated(
        &self,
        address: u64,
        output: &mut [u8],
        bias: u64,
        mut resolve: impl FnMut(u32, u32) -> Result<u64, Error>,
        mut descriptor: impl FnMut(u32, u64) -> Result<(u64, u64), Error>,
    ) -> Result<(), Error> {
        let length = output.len() as u64;
        let end = add(address, length)?;
        let segment = (0..self.count)
            .find_map(|index| {
                self.segment(index)
                    .ok()
                    .filter(|segment| segment.kind == LOAD && segment.contains(address, length))
            })
            .ok_or(Error::Invalid)?;
        output.fill(0);
        let within = address - segment.address;
        let file = segment.file.saturating_sub(within).min(length);
        if file != 0 {
            let source = extent(self.bytes, add(segment.offset, within)?, file)?;
            output[..file as usize].copy_from_slice(&self.bytes[source]);
        }
        self.relocations(|target, value| {
            let start = address.max(target);
            let finish = end.min(add(target, value.width())?);
            if start < finish {
                let (bytes, _) = value.encode(bias, &mut resolve, &mut descriptor)?;
                let source = (start - target) as usize;
                let destination = (start - address) as usize;
                let count = (finish - start) as usize;
                output[destination..destination + count]
                    .copy_from_slice(&bytes[source..source + count]);
            }
            Ok(())
        })
    }
}
