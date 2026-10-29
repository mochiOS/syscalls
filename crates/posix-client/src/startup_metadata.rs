//! Userspace metadata storage over generic initial VM mappings. Small process
//! stacks need no object; overflow moves only metadata, never truncates argv.
use crate::{
    image_preparation::Backend,
    newlib_errno::*,
    process_image::{self, EncodeError, Process},
};
use core::marker::PhantomData;
use mnu_abi::process_image::{self as wire, InitialMapping};
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
pub const READER_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_MAP;
const PAGE: usize = 4096;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    base: u64,
    length: usize,
    spans: [(usize, usize); 3],
}
impl Layout {
    pub fn new(base: u64, process: Process<'_>) -> Result<Self, EncodeError> {
        if base < 0x400000 || base % PAGE as u64 != 0 {
            return Err(EncodeError::InvalidText);
        }
        let mut cursor = 0usize;
        let mut spans = [(0, 0); 3];
        for (index, bytes) in [process.lifecycle, process.tls, process.indirect]
            .into_iter()
            .enumerate()
        {
            if bytes.is_empty() {
                continue;
            }
            cursor = cursor
                .checked_add(7)
                .map(|n| n & !7)
                .ok_or(EncodeError::ImageTooLarge)?;
            spans[index] = (cursor, bytes.len());
            cursor = cursor
                .checked_add(bytes.len())
                .ok_or(EncodeError::ImageTooLarge)?;
        }
        let length = cursor
            .checked_add(PAGE - 1)
            .map(|n| n & !(PAGE - 1))
            .filter(|n| *n != 0 && *n <= MAX_BYTES)
            .ok_or(EncodeError::ImageTooLarge)?;
        base.checked_add(length as u64)
            .filter(|end| *end <= 0x8000_0000_0000)
            .ok_or(EncodeError::ImageTooLarge)?;
        Ok(Self {
            base,
            length,
            spans,
        })
    }
    pub fn length(self) -> usize {
        self.length
    }
    pub fn address(self, index: usize) -> Option<u64> {
        self.spans
            .get(index)
            .filter(|(_, n)| *n != 0)
            .map(|(at, _)| self.base + *at as u64)
    }
    pub(crate) fn matches(self, process: Process<'_>) -> bool {
        [process.lifecycle, process.tls, process.indirect]
            .iter()
            .zip(self.spans)
            .all(|(b, (_, n))| b.len() == n)
    }
    fn mapping(self, handle: u32) -> InitialMapping {
        InitialMapping {
            address: self.base,
            length: self.length as u64,
            access: mnu_abi::MEMORY_ACCESS_READ,
            options: mnu_abi::MEMORY_MAP_SHARED,
            backing_handle: u64::from(handle),
            backing_offset: 0,
        }
    }
}
fn encoding(error: EncodeError) -> i32 {
    match error {
        EncodeError::ImageTooLarge | EncodeError::EmptyArgumentVector => E2BIG,
        EncodeError::InvalidText => EINVAL,
        EncodeError::Codec(_) => EIO,
    }
}
pub struct Owner<B: Backend> {
    handle: u32,
    layout: Option<Layout>,
    ready: bool,
    backend: PhantomData<fn() -> B>,
}
impl<B: Backend> Default for Owner<B> {
    fn default() -> Self {
        Self {
            handle: 0,
            layout: None,
            ready: false,
            backend: PhantomData,
        }
    }
}
impl<B: Backend> Drop for Owner<B> {
    fn drop(&mut self) {
        if self.handle != 0 {
            B::critical(|| B::close(self.handle));
        }
    }
}
impl<B: Backend> Owner<B> {
    pub fn mapping(&self) -> Option<InitialMapping> {
        self.ready
            .then(|| self.layout.unwrap().mapping(self.handle))
    }
    /// Preflight the complete mapped stack before allocating anything. The
    /// caller owns this resource through image creation/replacement, including
    /// callback-aware cleanup if the C frame is abandoned.
    pub fn encode(
        &mut self,
        backend: &B,
        argv: &[&[u8]],
        envp: &[&[u8]],
        execfn: &[u8],
        random: [u8; 16],
        auxiliary: &[(u64, u64)],
        process: Process<'_>,
        output: &mut [u8],
    ) -> Result<usize, i32> {
        if self.handle != 0 || self.ready {
            return Err(EINVAL);
        }
        match process_image::encode_initial_stack_for_process(
            argv, envp, execfn, random, auxiliary, process, output,
        ) {
            Ok(n) => return Ok(n),
            Err(EncodeError::ImageTooLarge) => {}
            Err(e) => return Err(encoding(e)),
        }
        let base = 0x3000_0000_0000
            + (u64::from_le_bytes(random[8..].try_into().unwrap()) & 0xffff) * MAX_BYTES as u64;
        let layout = Layout::new(base, process).map_err(encoding)?;
        let length = process_image::encode_initial_stack_with_metadata(
            argv, envp, execfn, random, auxiliary, process, layout, output,
        )
        .map_err(encoding)?;
        self.layout = Some(layout);
        B::critical(|| {
            self.handle = backend.create_image(layout.length)?;
            if self.handle == 0 {
                return Err(EIO);
            }
            Ok(())
        })?;
        for (bytes, (offset, _)) in [process.lifecycle, process.tls, process.indirect]
            .into_iter()
            .zip(layout.spans)
        {
            let mut written = 0;
            while written < bytes.len() {
                let end = bytes
                    .len()
                    .min(written.saturating_add(mnu_abi::provider::MAX_DATA_LEN));
                let n = backend.write_at(self.handle, &bytes[written..end], offset + written)?;
                if n == 0 || n > end - written {
                    return Err(EIO);
                }
                written += n;
            }
        }
        B::critical(|| {
            let reader = backend.readonly_metadata(self.handle)?;
            if reader == 0 || reader == self.handle {
                return Err(EIO);
            }
            B::close(self.handle);
            self.handle = reader;
            self.ready = true;
            Ok(())
        })?;
        Ok(length)
    }
    /// Attach metadata alongside existing generic reservations in one envelope.
    /// No source handle is inherited into the child's table; its mapping owns
    /// the backing object independently after the source reference is closed.
    pub fn attach(
        &self,
        output: &mut [u8],
        length: usize,
        existing: &[InitialMapping],
    ) -> Result<usize, i32> {
        let extra = self.mapping();
        let count = existing
            .len()
            .checked_add(usize::from(extra.is_some()))
            .filter(|n| *n <= wire::MAX_MAPPINGS)
            .ok_or(E2BIG)?;
        let empty = InitialMapping {
            address: 0,
            length: 0,
            access: 0,
            options: 0,
            backing_handle: 0,
            backing_offset: 0,
        };
        let mut records = [empty; wire::MAX_MAPPINGS];
        records[..existing.len()].copy_from_slice(existing);
        if let Some(mapping) = extra {
            records[existing.len()] = mapping;
        }
        wire::attach_mappings(output, length, &records[..count]).map_err(|_| EIO)
    }
}
