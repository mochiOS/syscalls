//! One fixed-address native container for a complete, already-captured scope.
//! Original per-object PHDR views stay intact in their source LOADs.
use super::super::{
    Error, GNU_STACK, LOAD, PAGE, PHDR, Segment, USER_MIN, add, page, u16_at, u32_at, u64_at,
};
use super::{Scope, ranges};

struct Layout {
    count: u16,
    metadata: u64,
    base: u64,
    entry: u64,
    length: usize,
}
impl Scope<'_, '_> {
    fn bundle_layout(&self) -> Result<Layout, Error> {
        let root = &self.objects[0];
        let entry = add(root.image.entry, root.bias)?;
        if !(0..root.image.count).any(|index| {
            root.image.segment(index).is_ok_and(|segment| {
                segment.flags & 1 != 0 && segment.contains(root.image.entry, 1)
            })
        }) {
            return Err(Error::Invalid);
        }
        let mut count = 2u64; // Container metadata LOAD and PHDR.
        let mut minimum = u64::MAX;
        for (index, object) in self.objects.iter().enumerate() {
            count = add(count, 1)?; // Keep each member's native metadata LOAD.
            for header in 0..object.image.count {
                let segment = object.image.segment(header)?;
                if segment.retained() && (index == 0 || segment.kind != GNU_STACK) {
                    count = add(count, 1)?;
                }
            }
            for (start, _) in ranges(object)? {
                minimum = minimum.min(start);
            }
        }
        // 0xffff denotes extended numbering, which this container does not use.
        if count >= u16::MAX as u64 {
            return Err(Error::Invalid);
        }
        let metadata = page(add(64, count.checked_mul(56).ok_or(Error::Overflow)?)?)?;
        let base = minimum
            .checked_sub(metadata)
            .filter(|base| *base >= USER_MIN)
            .ok_or(Error::Invalid)?;
        let mut length = metadata;
        for &index in self.order {
            length = add(
                page(length)?,
                self.objects[index].image.output_length()? as u64,
            )?;
        }
        Ok(Layout {
            count: count as u16,
            metadata,
            base,
            entry,
            length: usize::try_from(length).map_err(|_| Error::Overflow)?,
        })
    }

    /// Bytes needed for one native ELF containing every reachable member.
    pub fn bundle_length(&self) -> Result<usize, Error> {
        Ok(self.bundle_layout()?.length)
    }

    /// Build a complete native image before authorizing or installing it. An
    /// error invalidates the output; the caller must discard it without commit.
    /// This function neither acquires handles nor grants execution authority.
    pub fn write_bundle(&self, output: &mut [u8]) -> Result<usize, Error> {
        let layout = self.bundle_layout()?;
        if output.len() < layout.length {
            return Err(Error::BufferTooSmall);
        }
        output[..layout.length].fill(0);
        output[..64].copy_from_slice(&self.objects[0].image.bytes[..64]);
        output[16..18].copy_from_slice(&2u16.to_le_bytes());
        output[24..32].copy_from_slice(&layout.entry.to_le_bytes());
        output[32..40].copy_from_slice(&64u64.to_le_bytes());
        output[40..48].fill(0);
        output[56..58].copy_from_slice(&layout.count.to_le_bytes());
        output[58..64].fill(0);
        Segment {
            kind: LOAD,
            flags: 4,
            offset: 0,
            address: layout.base,
            file: layout.metadata,
            memory: layout.metadata,
            alignment: PAGE,
        }
        .write(output, 64);
        Segment {
            kind: PHDR,
            flags: 4,
            offset: 64,
            address: add(layout.base, 64)?,
            file: layout.count as u64 * 56,
            memory: layout.count as u64 * 56,
            alignment: 8,
        }
        .write(output, 120);
        let mut next = 176;
        let mut member_offset = layout.metadata;
        for &index in self.order {
            member_offset = page(member_offset)?;
            let length = self.objects[index].image.output_length()?;
            let start = usize::try_from(member_offset).map_err(|_| Error::Overflow)?;
            let (prefix, tail) = output.split_at_mut(start);
            let member = tail.get_mut(..length).ok_or(Error::BufferTooSmall)?;
            self.write(index, member)?;
            let count = u16_at(member, 56)? as usize;
            for header in 0..count {
                let offset = 64 + header * 56;
                let mut segment = Segment {
                    kind: u32_at(member, offset)?,
                    flags: u32_at(member, offset + 4)?,
                    offset: u64_at(member, offset + 8)?,
                    address: u64_at(member, offset + 16)?,
                    file: u64_at(member, offset + 32)?,
                    memory: u64_at(member, offset + 40)?,
                    alignment: u64_at(member, offset + 48)?,
                };
                if segment.kind == PHDR || (index != 0 && segment.kind == GNU_STACK) {
                    continue;
                }
                if segment.kind == LOAD || segment.file != 0 {
                    segment.offset = add(segment.offset, member_offset)?;
                }
                segment.write(prefix, next);
                next += 56;
            }
            member_offset = add(member_offset, length as u64)?;
        }
        if next != 64 + layout.count as usize * 56 {
            return Err(Error::Invalid);
        }
        Ok(layout.length)
    }
}
