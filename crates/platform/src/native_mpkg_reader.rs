use crate::handle::{self, Handle};
use crate::package::MpkgReader;
use crate::syscall::{NativeError, SysError};

/// Package input backed by an already-authorized native file Handle.
///
/// This reader borrows the Handle: the caller must keep it open, close it
/// afterwards. The caller supplies a cursor-independent metadata query for
/// that same Handle (for example POSIX fstat through its existing endpoint).
/// Neither length queries nor positioned reads change the shared cursor. No
/// path lookup, Handle duplication or additional authority is acquired here.
pub struct NativeMpkgReader {
    handle: Handle,
    length_query: fn(Handle) -> Result<u64, SysError>,
}

impl NativeMpkgReader {
    pub fn from_borrowed_handle(
        handle: Handle,
        length_query: fn(Handle) -> Result<u64, SysError>,
    ) -> Self {
        Self {
            handle,
            length_query,
        }
    }
}

impl MpkgReader for NativeMpkgReader {
    fn len(&mut self) -> Result<u64, SysError> {
        (self.length_query)(self.handle)
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
