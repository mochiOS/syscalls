//! Allocation-free validation of relocation write ranges.
use super::*;

#[derive(Clone, Copy)]
struct Cursor {
    group: usize,
    index: usize,
    next_base: Option<u64>,
    bitmap_base: u64,
    bitmap: u64,
}
impl Cursor {
    fn new(group: usize) -> Self {
        Self {
            group,
            index: 0,
            next_base: None,
            bitmap_base: 0,
            bitmap: 0,
        }
    }
    fn next(&mut self, image: &Pie<'_>) -> Result<Option<(u64, Value)>, Error> {
        if self.group == 0 {
            loop {
                if self.bitmap != 0 {
                    let bit = self.bitmap.trailing_zeros();
                    self.bitmap &= self.bitmap - 1;
                    let target = add(self.bitmap_base, u64::from(bit - 1) * 8)?;
                    return Ok(Some((
                        target,
                        Value::Relative(image.relative_word(target)?),
                    )));
                }
                if self.index == image.relr_count {
                    return Ok(None);
                }
                let word = u64_at(image.bytes, image.relr_offset + self.index * 8)?;
                self.index += 1;
                if word & 1 == 0 {
                    self.next_base = Some(add(word, 8)?);
                    return Ok(Some((word, Value::Relative(image.relative_word(word)?))));
                }
                let base = self.next_base.ok_or(Error::Invalid)?;
                self.next_base = Some(add(base, 63 * 8)?);
                self.bitmap_base = base;
                self.bitmap = word & !1;
            }
        }
        let (offset, count) = if self.group == 1 {
            (image.rela_offset, image.rela_count)
        } else {
            (image.plt_offset, image.plt_count)
        };
        while self.index < count {
            let position = offset + self.index * 24;
            self.index += 1;
            if let (target, Some(value)) = image.relocation(position)? {
                return Ok(Some((target, value)));
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Copy)]
struct Run {
    cursor: Cursor,
    remaining: usize,
    head: Option<(u64, Value)>,
}
impl Cursor {
    fn next_write(&mut self, image: &Pie<'_>) -> Result<Option<(u64, Value)>, Error> {
        while let Some((target, value)) = self.next(image)? {
            if value.width() != 0 {
                return Ok(Some((target, value)));
            }
        }
        Ok(None)
    }
}
impl Run {
    fn advance(&mut self, image: &Pie<'_>) -> Result<(), Error> {
        self.head = if self.remaining == 0 {
            None
        } else {
            self.remaining -= 1;
            Some(self.cursor.next_write(image)?.ok_or(Error::Invalid)?)
        };
        Ok(())
    }
}
impl Pie<'_> {
    // A fixed number of monotonic runs covers ordinary linker output without
    // allocating. Inputs exceeding this bound keep the exhaustive validator.
    pub(super) fn validate_ordered_relocation_writes(&self) -> Result<bool, Error> {
        let mut runs: [Option<Run>; 64] = [None; 64];
        let mut count = 0;
        for group in 0..3 {
            let mut cursor = Cursor::new(group);
            let mut last_end = 0;
            let mut active = None;
            loop {
                let before = cursor;
                let Some((target, value)) = cursor.next_write(self)? else {
                    break;
                };
                if active.is_none() || target < last_end {
                    if count == runs.len() {
                        return Ok(false);
                    }
                    runs[count] = Some(Run {
                        cursor: before,
                        remaining: 0,
                        head: None,
                    });
                    active = Some(count);
                    count += 1;
                }
                runs[active.unwrap()].as_mut().unwrap().remaining += 1;
                last_end = add(target, value.width())?;
            }
        }
        for run in runs[..count].iter_mut().flatten() {
            run.advance(self)?;
        }
        let mut end = 0;
        while let Some(group) = (0..count)
            .filter(|&i| runs[i].as_ref().unwrap().head.is_some())
            .min_by_key(|&i| runs[i].as_ref().unwrap().head.unwrap().0)
        {
            let run = runs[group].as_mut().unwrap();
            let (target, value) = run.head.take().unwrap();
            if target < end {
                return Err(Error::Invalid);
            }
            end = add(target, value.width())?;
            run.advance(self)?;
        }
        Ok(true)
    }
    // Dense tables with many unsorted runs use exact byte coverage in sparse
    // 64KiB windows. No heap allocation or scan across absent windows is needed.
    // Wide COPY writes retain the original exhaustive validation below.
    #[inline(never)]
    pub(super) fn validate_windowed_relocation_writes(&self) -> Result<bool, Error> {
        const WINDOW: u64 = 65536;
        let mut first = None;
        let mut wide = false;
        self.relocations(|target, value| {
            let width = value.width();
            wide |= width > 16;
            if width != 0 {
                first = Some(first.map_or(target, |old: u64| old.min(target)));
            }
            Ok(())
        })?;
        if wide {
            return Ok(false);
        }
        let mut next = first;
        while let Some(address) = next {
            let start = address & !(WINDOW - 1);
            let end = add(start, WINDOW)?;
            let mut occupied = [0u64; WINDOW as usize / 64];
            next = None;
            self.relocations(|target, value| {
                if value.width() == 0 {
                    return Ok(());
                }
                let limit = add(target, value.width())?;
                if target >= end {
                    next = Some(next.map_or(target, |old| old.min(target)));
                    return Ok(());
                }
                if limit <= start {
                    return Ok(());
                }
                if limit > end {
                    next = Some(next.map_or(end, |old| old.min(end)));
                }
                let mut bit = (target.max(start) - start) as usize;
                let last = (limit.min(end) - start) as usize;
                while bit < last {
                    let offset = bit % 64;
                    let count = (last - bit).min(64 - offset);
                    let mask = (u64::MAX >> (64 - count)) << offset;
                    let word = &mut occupied[bit / 64];
                    if *word & mask != 0 {
                        return Err(Error::Invalid);
                    }
                    *word |= mask;
                    bit += count;
                }
                Ok(())
            })?;
        }
        Ok(true)
    }
}
