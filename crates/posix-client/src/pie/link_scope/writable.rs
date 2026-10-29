//! Temporarily writable data LOADs. Executable LOADs are never promoted.
use super::super::{Segment, Value};
use super::{Error, LOAD, PAGE, Scope, USER_END, USER_MIN, add, page};
use crate::relocation_protection::Range;
impl Scope<'_, '_> {
    pub(super) fn readonly_write(
        &self,
        index: usize,
        segment: Segment,
        copies: bool,
    ) -> Result<bool, Error> {
        if segment.kind != LOAD || segment.flags != 4 {
            return Ok(false);
        }
        let mut found = false;
        self.objects[index].image.relocations(|target, value| {
            if segment.contains(target, value.width()) {
                found |= match value {
                    Value::Copy { index: symbol, .. } if copies && index == 0 => self
                        .copy_source(symbol)?
                        .is_some_and(|(_, _, length)| length != 0),
                    _ => self.indirect_fixup(index, target, value)?.is_some(),
                };
            }
            Ok(())
        })?;
        Ok(found)
    }
    /// Exact data-only mapping ranges which require temporary RW/NX access.
    /// Consumers must validate/capture all fixups first and restore every range
    /// to read-only before constructors, including on failed transactions.
    pub fn readonly_writes(
        &self,
        mut emit: impl FnMut(Range) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut resolvers = false;
        for (index, object) in self.objects.iter().enumerate() {
            object.image.relocations(|target, value| {
                resolvers |= self.indirect_fixup(index, target, value)?.is_some();
                Ok(())
            })?;
        }
        if !resolvers {
            return Ok(());
        }
        let copies = self.has_deferred_copies()?;
        for (index, object) in self.objects.iter().enumerate() {
            for header in 0..object.image.count {
                let s = object.image.segment(header)?;
                if self.readonly_write(index, s, copies)? {
                    let address = add(object.bias, s.address)? & !(PAGE - 1);
                    let end = page(add(add(object.bias, s.address)?, s.memory)?)?;
                    if address < USER_MIN || end > USER_END || address == end {
                        return Err(Error::Invalid);
                    }
                    emit(Range {
                        address,
                        length: end - address,
                    })?;
                }
            }
        }
        Ok(())
    }
}
