//! One explicitly selected interpreter, captured under the same reader and
//! input-authentication policy as the main executable. No pathname is reopened.
use super::*;
pub(super) struct Interpreter<B: Backend> {
    source: Buffer<B>,
    handle: u32,
}
impl<B: Backend> Default for Interpreter<B> {
    fn default() -> Self {
        Self {
            source: Buffer::default(),
            handle: 0,
        }
    }
}
impl<B: Backend> Drop for Interpreter<B> {
    fn drop(&mut self) {
        if self.handle != 0 {
            B::critical(|| B::close(self.handle));
        }
    }
}
impl<B: Backend> Interpreter<B> {
    pub(super) fn build(
        &mut self,
        root: &[u8],
        output: &mut Buffer<B>,
        backend: &B,
    ) -> Result<crate::process_image::Executable, c_int> {
        use crate::elf_launch::{Image, Launch};
        let main = Image::parse(root).map_err(|_| ENOEXEC)?;
        let path = main.interpreter().map_err(|_| ENOEXEC)?.ok_or(ENOEXEC)?;
        B::critical(|| {
            let file = backend.open_library(path)?;
            self.handle = file.handle;
            if file.handle == 0
                || file.rights & posix_protocol::CHECK_EXECUTABLE_RIGHTS
                    != posix_protocol::CHECK_EXECUTABLE_RIGHTS
            {
                return Err(EACCES);
            }
            backend.validate_library(file)
        })?;
        self.source.capture(
            backend,
            self.handle,
            MAX_IMAGE.checked_sub(root.len()).ok_or(EFBIG)?,
        )?;
        backend.validate_captured(Source::Interpreter { path }, self.source.bytes())?;
        let loader = Image::parse(self.source.bytes()).map_err(|_| ENOEXEC)?;
        let mut random = [0; 16];
        backend.entropy(&mut random)?;
        let launch = Launch::new(main, loader, random).map_err(|_| ENOEXEC)?;
        let length = launch.length();
        output.reserve(length)?;
        // SAFETY: output is a fresh retained allocation, disjoint from inputs.
        let bytes = unsafe { core::slice::from_raw_parts_mut(output.pointer, length) };
        if launch.write(bytes).map_err(|_| ENOEXEC)? != length {
            return Err(EIO);
        }
        output.length = length;
        Ok(launch.executable())
    }
}
