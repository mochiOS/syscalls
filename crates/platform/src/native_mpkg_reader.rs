use crate::handle::{self, Handle};
use crate::package::MpkgReader;
use crate::syscall::{NativeError, SysError};

/// Package input backed by an already-authorized native file Handle.
///
/// This reader borrows the Handle: the caller must keep it open, close it
/// afterwards. `len` moves the shared cursor to EOF, so callers must exclude
/// concurrent cursor users during that call. Positioned reads do not use or
/// change the shared cursor. No path lookup or additional authority is acquired.
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
        offset
            .checked_add(output.len() as u64)
            .ok_or_else(|| SysError::from_raw(NativeError::LimitExceeded.into_raw() as i64))?;
        let mut done = 0;
        while done < output.len() {
            let count = handle::read_at(self.handle, &mut output[done..], offset + done as u64)?;
            if count == 0 || count > output.len() - done {
                return Err(SysError::from_raw(
                    NativeError::BackingFailure.into_raw() as i64
                ));
            }
            done += count;
        }
        Ok(())
    }
}
