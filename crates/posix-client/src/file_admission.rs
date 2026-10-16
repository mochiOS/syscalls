//! Retry only an authenticated, validated pre-mutation admission response.
//! Scheduling and signal delivery belong to the caller, never the service.
//! Callers retain source Handle leases until completion, including waits.
//! Wait callbacks return normally (or unwind Rust); C nonlocal jumps across
//! this owner are not supported. libc must retire owned positions before
//! invoking handlers which can abandon or reenter the pending operation.
use core::sync::atomic::Ordering;
use crate::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport, OpenAtBase,
    StatAtBase,
};
use mochios_posix_protocol::{self as protocol, STATUS_MEMORY_ADMISSION_BUSY};

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E, W> {
    Operation(ClientError<E>),
    Wait(W),
}

impl<E, W> From<ClientError<E>> for Error<E, W> {
    fn from(error: ClientError<E>) -> Self {
        Self::Operation(error)
    }
}

const TICKET_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_TRANSFER;

/// Immutable input snapshot, not ownership of native references or a retry
/// guarantee. Keep the source leases alive until the logical operation ends.
/// After an interrupted pre-storage wait the caller may deliver signals, then
/// execute this same snapshot again without touching an application pathname.
pub struct Prepared<H, const SIZE: usize> {
    opcode: u16,
    payload: [u8; SIZE],
    length: usize,
    sources: ObjectHandles<H>,
    success_objects: usize,
}

pub type PreparedOpen<H> =
    Prepared<H, { protocol::HEADER_LEN + protocol::OPEN_AT_HEADER_LEN + protocol::MAX_PATH_LEN }>;
pub type PreparedLength<H> =
    Prepared<H, { protocol::HEADER_LEN + protocol::FILE_LENGTH_PAYLOAD_LEN }>;
pub type PreparedTruncate<H> = Prepared<
    H,
    { protocol::HEADER_LEN + protocol::TRUNCATE_AT_HEADER_LEN + protocol::MAX_PATH_LEN },
>;

struct Owned<'a, T: ObjectTransport> {
    transport: &'a T,
    object: ObjectHandleAttachment<T::Handle>,
}
impl<T: ObjectTransport> Drop for Owned<'_, T> {
    fn drop(&mut self) {
        self.transport.close_received_handle(self.object.handle);
    }
}

/// Covers every response parsing/error path, including transport failures.
/// Some transports leave request labels in their output on failure; those
/// labels are borrows and must not be mistaken for newly received ownership.
struct Received<'a, T: ObjectTransport> {
    transport: &'a T,
    handles: ObjectHandles<T::Handle>,
    borrowed: ObjectHandles<T::Handle>,
}
impl<T: ObjectTransport> Received<'_, T> {
    fn only(&self) -> Option<ObjectHandleAttachment<T::Handle>> {
        let object = self.handles.get(0)?;
        (self.handles.len() == 1
            && object.handle != T::Handle::default()
            && !self
                .borrowed
                .iter()
                .any(|source| source.handle == object.handle))
        .then_some(object)
    }
    fn take_only(&mut self) -> Option<ObjectHandleAttachment<T::Handle>> {
        let object = self.only()?;
        self.handles.clear();
        Some(object)
    }
}
impl<T: ObjectTransport> Drop for Received<'_, T> {
    fn drop(&mut self) {
        crate::drain_received_handles(&mut self.handles, &self.borrowed, |handle| {
            self.transport.close_received_handle(handle)
        });
    }
}

impl<T: ObjectTransport> Client<T> {
    /// Snapshot the path before the first RPC. `wait` borrows a validated
    /// WAIT|TRANSFER position and must return normally without closing it.
    /// Its error cancels the position. No libc/FD-table locks may span wait.
    pub fn open_at_with_wait<W>(
        &self,
        base: OpenAtBase<T::Handle>,
        options: u32,
        mode: u32,
        path: impl AsRef<[u8]>,
        wait: impl FnMut(&ObjectHandleAttachment<T::Handle>) -> Result<(), W>,
    ) -> Result<ObjectHandleAttachment<T::Handle>, Error<T::Error, W>> {
        let prepared = self.prepare_open_at(base, options, mode, path)?;
        self.execute_file_mutation(&prepared, wait)?
            .ok_or(ClientError::MismatchedResponse.into())
    }

    pub fn prepare_open_at(
        &self,
        base: OpenAtBase<T::Handle>,
        options: u32,
        mode: u32,
        path: impl AsRef<[u8]>,
    ) -> Result<PreparedOpen<T::Handle>, ClientError<T::Error>> {
        let (base, directory) = match base {
            OpenAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
            OpenAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
            OpenAtBase::Directory(handle) => (protocol::OpenBase::AttachedDirectory, Some(handle)),
        };
        let mut payload =
            [0; protocol::HEADER_LEN + protocol::OPEN_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
        let len = protocol::encode_open_at(
            protocol::OpenAtRequest {
                base,
                options,
                mode,
                path: path.as_ref(),
            },
            &mut payload,
        )
        .map_err(ClientError::Protocol)?;
        let handles = Self::mutation_source(directory, mnu_abi::HANDLE_RIGHT_READ)?;
        Ok(Prepared {
            opcode: protocol::OP_OPEN_AT,
            payload,
            length: len,
            sources: handles,
            success_objects: 1,
        })
    }

    pub fn ftruncate_with_wait<W>(
        &self,
        file: ObjectHandleAttachment<T::Handle>,
        length: u64,
        wait: impl FnMut(&ObjectHandleAttachment<T::Handle>) -> Result<(), W>,
    ) -> Result<(), Error<T::Error, W>> {
        let prepared = self.prepare_ftruncate(file, length)?;
        self.execute_file_mutation(&prepared, wait).map(|_| ())
    }

    pub fn prepare_ftruncate(
        &self,
        file: ObjectHandleAttachment<T::Handle>,
        length: u64,
    ) -> Result<PreparedLength<T::Handle>, ClientError<T::Error>> {
        let mut payload = [0; protocol::HEADER_LEN + protocol::FILE_LENGTH_PAYLOAD_LEN];
        protocol::encode_file_length(length, &mut payload[..protocol::FILE_LENGTH_PAYLOAD_LEN])
            .map_err(ClientError::Protocol)?;
        let handles = Self::mutation_source(Some(file), mnu_abi::HANDLE_RIGHT_WRITE)?;
        Ok(Prepared {
            opcode: protocol::OP_FTRUNCATE,
            payload,
            length: protocol::FILE_LENGTH_PAYLOAD_LEN,
            sources: handles,
            success_objects: 0,
        })
    }

    pub fn truncate_at_with_wait<W>(
        &self,
        base: StatAtBase<T::Handle>,
        path: impl AsRef<[u8]>,
        length: u64,
        wait: impl FnMut(&ObjectHandleAttachment<T::Handle>) -> Result<(), W>,
    ) -> Result<(), Error<T::Error, W>> {
        let prepared = self.prepare_truncate_at(base, path, length)?;
        self.execute_file_mutation(&prepared, wait).map(|_| ())
    }

    pub fn prepare_truncate_at(
        &self,
        base: StatAtBase<T::Handle>,
        path: impl AsRef<[u8]>,
        length: u64,
    ) -> Result<PreparedTruncate<T::Handle>, ClientError<T::Error>> {
        let (base, directory) = match base {
            StatAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
            StatAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
            StatAtBase::Directory(handle) => (protocol::OpenBase::AttachedDirectory, Some(handle)),
        };
        let mut payload =
            [0; protocol::HEADER_LEN + protocol::TRUNCATE_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
        let len = protocol::encode_truncate_at(
            protocol::TruncateAtRequest {
                base,
                length,
                path: path.as_ref(),
            },
            &mut payload,
        )
        .map_err(ClientError::Protocol)?;
        let handles = Self::mutation_source(directory, mnu_abi::HANDLE_RIGHT_READ)?;
        Ok(Prepared {
            opcode: protocol::OP_TRUNCATE_AT,
            payload,
            length: len,
            sources: handles,
            success_objects: 0,
        })
    }

    /// One invocation owns all received references until success or error.
    /// In particular Error::Wait returns AFTER cancelling the current ticket.
    /// A transport/storage error does not authorize a second invocation.
    pub fn execute_file_mutation<const SIZE: usize, W>(
        &self,
        prepared: &Prepared<T::Handle, SIZE>,
        wait: impl FnMut(&ObjectHandleAttachment<T::Handle>) -> Result<(), W>,
    ) -> Result<Option<ObjectHandleAttachment<T::Handle>>, Error<T::Error, W>> {
        self.queued_mutation::<SIZE, W>(
            prepared.opcode,
            &prepared.payload[..prepared.length],
            prepared.sources.clone(),
            prepared.success_objects,
            wait,
        )
    }

    fn mutation_source(
        source: Option<ObjectHandleAttachment<T::Handle>>,
        required: u64,
    ) -> Result<ObjectHandles<T::Handle>, ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        if let Some(mut source) = source {
            let required = required | mnu_abi::HANDLE_RIGHT_TRANSFER;
            if source.handle == T::Handle::default() || source.rights & required != required {
                return Err(ClientError::Remote(-13));
            }
            source.rights = required;
            handles
                .push(source)
                .map_err(|_| ClientError::RequestTooLarge)?;
        }
        Ok(handles)
    }

    // The serialized input is an owned stack snapshot, not the application's
    // possibly file-backed path. Only this snapshot is reframed on retry.
    fn queued_mutation<const SIZE: usize, W>(
        &self,
        opcode: u16,
        payload: &[u8],
        sources: ObjectHandles<T::Handle>,
        success_objects: usize,
        mut wait: impl FnMut(&ObjectHandleAttachment<T::Handle>) -> Result<(), W>,
    ) -> Result<Option<ObjectHandleAttachment<T::Handle>>, Error<T::Error, W>> {
        let mut ticket: Option<Owned<'_, T>> = None;
        loop {
            let mut outgoing = sources.clone();
            let mut flags = protocol::MUTATION_ADMISSION;
            if let Some(ticket) = ticket.as_ref() {
                outgoing
                    .push(ticket.object)
                    .map_err(|_| ClientError::RequestTooLarge)?;
                flags |= protocol::MUTATION_ADMISSION_ATTACHED;
            }
            let mut received = Received {
                transport: &self.transport,
                borrowed: outgoing.clone(),
                handles: outgoing,
            };
            let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
            let mut request = [0; SIZE];
            let length = protocol::encode(
                protocol::Header {
                    opcode,
                    request_id,
                    flags,
                    payload_len: payload.len() as u32,
                    status: 0,
                },
                payload,
                &mut request,
            )
            .map_err(ClientError::Protocol)?;
            let mut response = [0; protocol::HEADER_LEN + 1];
            let length = self
                .transport
                .call_with_handles(&request[..length], &mut response, &mut received.handles)
                .map_err(ClientError::Transport)?;
            let response = response
                .get(..length)
                .ok_or(ClientError::ResponseTooLarge)?;
            let (header, body) = protocol::decode(response).map_err(ClientError::Protocol)?;
            if header.opcode != protocol::OP_STATUS
                || header.request_id != request_id
                || header.flags != 0
                || !body.is_empty()
                || header.status > 0
            {
                return Err(ClientError::MismatchedResponse.into());
            }
            if header.status == protocol::STATUS_MEMORY_ADMISSION_BUSY {
                let next = received
                    .only()
                    .filter(|object| object.rights == TICKET_RIGHTS)
                    .ok_or(ClientError::MismatchedResponse)?;
                received.take_only();
                drop(received);
                // The previous position remains alive until its replacement
                // has crossed IPC and passed validation; close each once.
                ticket = Some(Owned {
                    transport: &self.transport,
                    object: next,
                });
                wait(
                    &ticket
                        .as_ref()
                        .ok_or(ClientError::MismatchedResponse)?
                        .object,
                )
                .map_err(Error::Wait)?;
            } else if header.status != 0 {
                if !received.handles.is_empty() {
                    return Err(ClientError::MismatchedResponse.into());
                }
                return Err(ClientError::Remote(header.status).into());
            } else {
                if received.handles.len() != success_objects {
                    return Err(ClientError::MismatchedResponse.into());
                }
                return if success_objects == 1 {
                    received
                        .take_only()
                        .map(Some)
                        .ok_or(ClientError::MismatchedResponse.into())
                } else {
                    Ok(None)
                };
            }
        }
    }
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
