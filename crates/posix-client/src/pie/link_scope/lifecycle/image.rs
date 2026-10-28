//! Flatten relocated callbacks into the userspace startup codec. The producer
//! verifies every function against the captured scope before publishing it.
use super::super::super::{Error, add, extent, u16_at, u32_at, u64_at};
use super::{Lifecycle, Step};
use crate::lifecycle_image::{HEADER_BYTES, MAGIC, OBJECT_BYTES, VERSION};

fn callback_count(step: Step) -> u64 {
    match step {
        Step::Function { .. } => 1,
        Step::Array { count, .. } => count,
    }
}
fn loaded_word(bytes: &[u8], address: u64) -> Result<u64, Error> {
    let offset = u64_at(bytes, 32)?;
    let count = u16_at(bytes, 56)? as u64;
    let table = extent(bytes, offset, count * 56)?;
    for header in table.step_by(56) {
        if u32_at(bytes, header)? != 1 {
            continue;
        }
        let base = u64_at(bytes, header + 16)?;
        let memory = u64_at(bytes, header + 40)?;
        if address < base || add(address, 8)? > add(base, memory)? {
            continue;
        }
        let within = address - base;
        let file = u64_at(bytes, header + 32)?;
        let length = file.saturating_sub(within).min(8);
        let mut word = [0; 8];
        if length != 0 {
            let source = extent(bytes, add(u64_at(bytes, header + 8)?, within)?, length)?;
            word[..length as usize].copy_from_slice(&bytes[source]);
        }
        return Ok(u64::from_le_bytes(word));
    }
    Err(Error::Invalid)
}
fn put(output: &mut [u8], at: usize, value: u64) -> Result<(), Error> {
    output
        .get_mut(at..at.checked_add(8).ok_or(Error::Overflow)?)
        .ok_or(Error::BufferTooSmall)?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}
impl Lifecycle<'_, '_, '_> {
    /// Zero denotes a scope needing no lifecycle runner. Otherwise includes a
    /// descriptor per object in dependency order and all resolved callbacks.
    pub fn encoded_length(&self) -> Result<usize, Error> {
        let mut calls = 0u64;
        let mut overflow = false;
        let mut count = |step| match calls.checked_add(callback_count(step)) {
            Some(value) => calls = value,
            None => overflow = true,
        };
        self.initializers(&mut count)?;
        self.finalizers(&mut count)?;
        if overflow {
            return Err(Error::Overflow);
        }
        if calls == 0 {
            return Ok(0);
        }
        let descriptors = self
            .order
            .len()
            .checked_mul(OBJECT_BYTES)
            .ok_or(Error::Overflow)?;
        usize::try_from(calls)
            .ok()
            .and_then(|calls| calls.checked_mul(8))
            .and_then(|calls| HEADER_BYTES.checked_add(descriptors)?.checked_add(calls))
            .ok_or(Error::Overflow)
    }

    fn encode_step(
        &self,
        step: Step,
        bundle: &[u8],
        output: &mut [u8],
        cursor: &mut usize,
    ) -> Result<(), Error> {
        for index in 0..callback_count(step) {
            let address = match step {
                Step::Function { address, .. } => address,
                Step::Array {
                    address,
                    count,
                    reverse,
                    ..
                } => {
                    let index = if reverse { count - index - 1 } else { index };
                    loaded_word(
                        bundle,
                        add(address, index.checked_mul(8).ok_or(Error::Overflow)?)?,
                    )?
                }
            };
            if !self.is_callable(address) {
                return Err(Error::Invalid);
            }
            put(output, *cursor, address)?;
            *cursor = cursor.checked_add(8).ok_or(Error::Overflow)?;
        }
        Ok(())
    }

    /// `bundle` must be the immutable output of this scope's write_bundle.
    /// No source-image pointer or unrelocated array element enters the codec.
    /// On any error the caller must discard the entire output.
    pub fn encode_prepared(&self, bundle: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let length = self.encoded_length()?;
        if length == 0 {
            return Ok(0);
        }
        if output.len() < length {
            return Err(Error::BufferTooSmall);
        }
        let count = u32::try_from(self.order.len()).map_err(|_| Error::Overflow)?;
        put(output, 0, MAGIC)?;
        put(output, 8, u64::from(VERSION) | (u64::from(count) << 32))?;
        put(output, 16, length as u64)?;
        let root = self.scope.objects[0].image.lifecycle;
        put(output, 24, root.preinit.count)?;
        let mut cursor = HEADER_BYTES + self.order.len() * OBJECT_BYTES;
        let mut steps = [None; 2];
        self.array(0, root.preinit, false, &mut |step| steps[0] = Some(step))?;
        if let Some(step) = steps[0].take() {
            self.encode_step(step, bundle, output, &mut cursor)?;
        }
        for (position, &object) in self.order.iter().enumerate() {
            let metadata = self.scope.objects[object].image.lifecycle;
            let descriptor = HEADER_BYTES + position * OBJECT_BYTES;
            put(output, descriptor, cursor as u64)?;
            put(
                output,
                descriptor + 8,
                add(u64::from(metadata.init != 0), metadata.initialize.count)?,
            )?;
            self.function(object, metadata.init, &mut |step| steps[0] = Some(step))?;
            self.array(object, metadata.initialize, false, &mut |step| {
                steps[1] = Some(step)
            })?;
            for step in &mut steps {
                if let Some(step) = step.take() {
                    self.encode_step(step, bundle, output, &mut cursor)?;
                }
            }
            put(output, descriptor + 16, cursor as u64)?;
            put(
                output,
                descriptor + 24,
                add(u64::from(metadata.fini != 0), metadata.finalize.count)?,
            )?;
            self.array(object, metadata.finalize, true, &mut |step| {
                steps[0] = Some(step)
            })?;
            self.function(object, metadata.fini, &mut |step| steps[1] = Some(step))?;
            for step in &mut steps {
                if let Some(step) = step.take() {
                    self.encode_step(step, bundle, output, &mut cursor)?;
                }
            }
        }
        if cursor != length {
            return Err(Error::Invalid);
        }
        Ok(length)
    }
}
