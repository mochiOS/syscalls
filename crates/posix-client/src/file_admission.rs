//! Retry only an authenticated, validated pre-mutation admission response.
//! Scheduling and signal delivery belong to the caller, never the service.
use crate::ClientError;
use mochios_posix_protocol::STATUS_MEMORY_ADMISSION_BUSY;

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E, W> {
    Operation(ClientError<E>),
    Wait(W),
}

/// Keep operation arguments and borrowed Handle leases alive across retries.
/// `wait` must run without FD-table/runtime locks and permit other threads to
/// make progress. Its failure (including signal interruption) ends the loop.
/// No transport error, ordinary EAGAIN or post-mutation failure is replayed.
pub fn retry<T, E, W>(
    mut operation: impl FnMut() -> Result<T, ClientError<E>>,
    mut wait: impl FnMut() -> Result<(), W>,
) -> Result<T, Error<E, W>> {
    loop {
        match operation() {
            Err(ClientError::Remote(STATUS_MEMORY_ADMISSION_BUSY)) => {
                wait().map_err(Error::Wait)?;
            }
            result => return result.map_err(Error::Operation),
        }
    }
}
