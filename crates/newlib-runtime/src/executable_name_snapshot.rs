//! Owned startup pathname metadata. This is never execution authority.
use super::*;

pub(super) struct Name {
    pub bytes: [u8; posix_protocol::MAX_PATH_LEN + 1],
    length: usize,
    error: c_int,
}

impl Name {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; posix_protocol::MAX_PATH_LEN + 1],
            length: 0,
            error: ENOENT,
        }
    }
    pub fn capture(resolve: impl FnOnce(&mut [u8]) -> Result<usize, c_int>) -> Self {
        let mut name = Self::empty();
        match resolve(&mut name.bytes[..posix_protocol::MAX_PATH_LEN]) {
            Ok(length)
                if length > 0
                    && length <= posix_protocol::MAX_PATH_LEN
                    && name.bytes[0] == b'/'
                    && !name.bytes[..length].contains(&0) =>
            {
                name.length = length;
                name.error = 0;
                name.bytes[length] = 0;
            }
            Ok(_) => name.error = EIO,
            Err(error) => name.error = if error > 0 { error } else { EIO },
        }
        name
    }
    pub fn value(&self) -> Result<&[u8], c_int> {
        if self.error == 0 {
            Ok(&self.bytes[..self.length])
        } else {
            Err(self.error)
        }
    }
}
