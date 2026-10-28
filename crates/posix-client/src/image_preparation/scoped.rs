//! Loader reader restricted to one explicitly delegated pathname scope.
use super::*;
use crate::{Client, ClientError, ObjectHandleAttachment, ObjectTransport};

/// Resource mechanisms come from B; pathname access and credentials come only
/// from the attached scope. The scope is borrowed and must remain owned by the
/// caller for this reader's lifetime. No ambient open fallback is performed.
pub struct Scoped<'a, T: ObjectTransport<Handle = u32>, B: Backend> {
    client: &'a Client<T>,
    scope: ObjectHandleAttachment<u32>,
    mechanisms: &'a B,
    identity: crate::process_image::Identity,
    error: fn(ClientError<T::Error>) -> c_int,
}

impl<'a, T: ObjectTransport<Handle = u32>, B: Backend> Scoped<'a, T, B> {
    pub fn new(
        client: &'a Client<T>,
        scope: ObjectHandleAttachment<u32>,
        mechanisms: &'a B,
        error: fn(ClientError<T::Error>) -> c_int,
    ) -> Result<Self, c_int> {
        let info = B::critical(|| client.read_scope_info(scope).map_err(error))?;
        Ok(Self {
            client,
            scope,
            mechanisms,
            identity: info.into(),
            error,
        })
    }

    pub fn identity(&self) -> crate::process_image::Identity {
        self.identity
    }

    /// Apply the same authenticated identity to dependency search and prepared
    /// startup metadata; an ambient broker session is never substituted.
    pub fn prepare<'p>(
        &self,
        owner: &'p mut Preparation<Self>,
        image: u32,
        environment: Environment<'_>,
    ) -> Result<Prepared<'p>, c_int> {
        owner.prepare(self, image, environment, self.identity)
    }
}

// Storage, critical sections and reference lifetime obey B's contract. Only
// the reader changes: native scope identity/rights are verified by the service.
unsafe impl<T: ObjectTransport<Handle = u32>, B: Backend> Backend for Scoped<'_, T, B> {
    fn critical<R>(operation: impl FnOnce() -> R) -> R {
        B::critical(operation)
    }
    fn allocate(length: usize) -> *mut u8 {
        B::allocate(length)
    }
    unsafe fn deallocate(pointer: *mut u8) {
        unsafe { B::deallocate(pointer) };
    }
    fn close(handle: u32) {
        B::close(handle)
    }
    fn read_at(&self, image: u32, output: &mut [u8], offset: usize) -> Result<usize, c_int> {
        self.mechanisms.read_at(image, output, offset)
    }
    fn open_library(&self, path: &[u8]) -> Result<ObjectHandleAttachment<u32>, c_int> {
        self.client
            .read_scope_open(self.scope, path.first() == Some(&b'/'), path)
            .map_err(self.error)
    }
    fn validate_library(&self, file: ObjectHandleAttachment<u32>) -> Result<(), c_int> {
        let status = self.client.fstat(file).map_err(self.error)?;
        if status.mode & 0o170000 != 0o100000 {
            return Err(ENOEXEC);
        }
        Ok(())
    }
    fn entropy(&self, output: &mut [u8]) -> Result<(), c_int> {
        self.mechanisms.entropy(output)
    }
    fn create_image(&self, length: usize) -> Result<u32, c_int> {
        self.mechanisms.create_image(length)
    }
    fn write_at(&self, image: u32, bytes: &[u8], offset: usize) -> Result<usize, c_int> {
        self.mechanisms.write_at(image, bytes, offset)
    }
    fn readonly_image(&self, image: u32) -> Result<u32, c_int> {
        self.mechanisms.readonly_image(image)
    }
}
