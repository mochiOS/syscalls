//! Page protection follows GNU RELRO's rounded-down start and end convention.
use super::{Error, LOAD, PAGE, Pie, RELRO, USER_END, USER_MIN, add, page};
use crate::relocation_protection::Range;
impl Pie<'_> {
    pub fn relro(
        &self,
        bias: u64,
        mut emit: impl FnMut(Range) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if bias % PAGE != 0 {
            return Err(Error::Invalid);
        }
        for i in 0..self.count {
            let s = self.segment(i)?;
            if s.kind != RELRO {
                continue;
            }
            if s.file > s.memory {
                return Err(Error::Invalid);
            }
            if s.memory == 0 {
                continue;
            }
            let end = add(s.address, s.memory)?;
            if s.file > s.memory
                || !(0..self.count).any(|j| {
                    self.segment(j).is_ok_and(|load| {
                        load.kind == LOAD
                            && load.flags & 4 != 0
                            && load.contains(s.address, s.memory)
                    })
                })
            {
                return Err(Error::Invalid);
            }
            let start = add(bias, s.address)? & !(PAGE - 1);
            let end = add(bias, end)? & !(PAGE - 1);
            if start < USER_MIN && bias != 0 || end > USER_END {
                return Err(Error::Invalid);
            }
            if start == end {
                continue;
            }
            // Rounded protection may include the prefix of the first page,
            // but must remain wholly within this LOAD's mapped page extent.
            if !(0..self.count).any(|j| {
                self.segment(j).is_ok_and(|load| {
                    load.kind == LOAD
                        && add(bias, load.address).is_ok_and(|a| a & !(PAGE - 1) <= start)
                        && add(bias, load.address)
                            .and_then(|a| add(a, load.memory))
                            .and_then(page)
                            .is_ok_and(|last| end <= last)
                })
            }) {
                return Err(Error::Invalid);
            }
            emit(Range {
                address: start,
                length: end - start,
            })?;
        }
        Ok(())
    }
    pub fn has_relro(&self) -> Result<bool, Error> {
        let mut found = false;
        self.relro(0, |_| {
            found = true;
            Ok(())
        })?;
        Ok(found)
    }
    pub fn has_relro_runtime(&self) -> Result<bool, Error> {
        self.has_runtime_marker(b"__mochios_relro_v1")
    }
}
