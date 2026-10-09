use crate::handle::{self, Handle};
use crate::package::MpkgReader;
use crate::syscall::{EIO, ERANGE, SysError};

/// Package input backed by an already-authorized native file Handle.
///
/// This reader borrows the Handle: the caller must keep it open, close it
/// afterwards, and prevent other users from moving its shared cursor while
/// parsing. No path lookup or additional authority is acquired here.
pub struct NativeMpkgReader {
    handle: Handle,
}

impl NativeMpkgReader {
    pub fn from_borrowed_handle(handle: Handle) -> Self {
        Self { handle }
    }
}

impl MpkgReader for NativeMpkgReader {
    fn len(&mut self) -> Result<u64, SysError> {
        handle::seek(self.handle, 0, handle::HANDLE_SEEK_END)
    }

    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), SysError> {
        let offset = i64::try_from(offset).map_err(|_| SysError::from_raw(ERANGE as i64))?;
        handle::seek(self.handle, offset, handle::HANDLE_SEEK_START)?;
        let mut done = 0;
        while done < output.len() {
            let count = handle::read(self.handle, &mut output[done..])?;
            if count == 0 || count > output.len() - done {
                return Err(SysError::from_raw(EIO as i64));
            }
            done += count;
        }
        Ok(())
    }
}
