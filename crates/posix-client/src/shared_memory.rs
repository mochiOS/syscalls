//! Named RAM control operations; mapped data and extent changes use native
//! Handle operations without routing frequent accesses through the service.

use crate::{
    Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport,
    drain_received_handles,
};
use core::sync::atomic::Ordering;
use mochios_posix_protocol::{self as protocol, shared_memory as wire};

/// Serialized request and response contract, not ownership of either Handle.
/// A nonlocal-jump-capable runtime must publish its native receive envelope
/// before IPC and retain its ownership through validation and consumption.
pub struct PreparedBacking<H> {
    frame: [u8; protocol::HEADER_LEN + 4],
    request_id: u64,
    descriptor: ObjectHandleAttachment<H>,
    rights: u64,
}

/// Owned serialized name request; reply validation does not consume Handles.
pub struct PreparedNamespace {
    frame: [u8; protocol::HEADER_LEN + wire::OPEN_HEADER_LEN + wire::MAX_NAME_BYTES + 1],
    length: usize,
    request_id: u64,
    rights: Option<u64>,
}

fn validate_status<E>(request_id: u64, response: &[u8]) -> Result<(), ClientError<E>> {
    let (header, payload) = protocol::decode(response).map_err(ClientError::Protocol)?;
    if header.opcode != protocol::OP_STATUS
        || header.request_id != request_id
        || header.flags != 0
        || header.status > 0
        || header.status == protocol::STATUS_MEMORY_ADMISSION_BUSY
    {
        return Err(ClientError::MismatchedResponse);
    }
    if header.status != protocol::STATUS_OK {
        return Err(ClientError::Remote(header.status));
    }
    if !payload.is_empty() {
        return Err(ClientError::ResponseTooLarge);
    }
    Ok(())
}

impl PreparedNamespace {
    pub fn request(&self) -> &[u8] {
        &self.frame[..self.length]
    }
    pub fn validate<H: Copy + Default + Eq, E>(
        &self,
        response: &[u8],
        handles: &ObjectHandles<H>,
    ) -> Result<Option<ObjectHandleAttachment<H>>, ClientError<E>> {
        validate_status(self.request_id, response)?;
        if let Some(rights) = self.rights {
            let received = handles.get(0).ok_or(ClientError::MismatchedResponse)?;
            if handles.len() != 1 || received.handle == H::default() || received.rights != rights {
                return Err(ClientError::MismatchedResponse);
            }
            Ok(Some(received))
        } else if handles.is_empty() {
            Ok(None)
        } else {
            Err(ClientError::MismatchedResponse)
        }
    }
}

impl<H: Copy + Default + PartialEq> PreparedBacking<H> {
    pub fn request(&self) -> &[u8] {
        &self.frame
    }
    pub fn descriptor(&self) -> ObjectHandleAttachment<H> {
        self.descriptor
    }

    /// Validate only. The receive-envelope owner still owns every attachment,
    /// including the returned label; this method never closes or transfers it.
    pub fn validate<E>(
        &self,
        response: &[u8],
        handles: &ObjectHandles<H>,
    ) -> Result<ObjectHandleAttachment<H>, ClientError<E>> {
        validate_status(self.request_id, response)?;
        let received = handles.get(0).ok_or(ClientError::MismatchedResponse)?;
        if handles.len() != 1
            || received.handle == H::default()
            || received.handle == self.descriptor.handle
            || received.rights != self.rights
        {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(received)
    }
}

pub fn rights(read_write: bool) -> u64 {
    wire::descriptor_rights(read_write)
}

/// Decode newlib's shm_open flags without passing libc flag values to mnu.
/// FD_CLOEXEC is mandatory for shm_open and handled by the local FD table.
pub fn newlib_open_options(flags: i32) -> Option<u32> {
    const CREATE: i32 = 0x0200;
    const TRUNCATE: i32 = 0x0400;
    const EXCLUSIVE: i32 = 0x0800;
    const CLOEXEC: i32 = 0x40000;
    if flags & !(3 | CREATE | TRUNCATE | EXCLUSIVE | CLOEXEC) != 0
        || flags & EXCLUSIVE != 0 && flags & CREATE == 0
    {
        return None;
    }
    let mut options = match flags & 3 {
        0 => 0,
        2 => wire::READ_WRITE,
        _ => return None,
    };
    if flags & TRUNCATE != 0 && options & wire::READ_WRITE == 0 {
        return None;
    }
    for (flag, option) in [
        (CREATE, wire::CREATE),
        (TRUNCATE, wire::TRUNCATE),
        (EXCLUSIVE, wire::EXCLUSIVE),
    ] {
        if flags & flag != 0 {
            options |= option;
        }
    }
    Some(options)
}

impl<T: ObjectTransport> Client<T> {
    pub fn prepare_shared_memory_open(
        &self,
        request: wire::Open<'_>,
    ) -> Result<PreparedNamespace, ClientError<T::Error>> {
        let mut payload = [0; wire::OPEN_HEADER_LEN + wire::MAX_NAME_BYTES + 1];
        let length = wire::encode_open(request, &mut payload).map_err(ClientError::Protocol)?;
        self.prepare_shared_memory_namespace(
            protocol::OP_SHARED_MEMORY_OPEN,
            &payload[..length],
            Some(rights(request.options & wire::READ_WRITE != 0)),
        )
    }

    pub fn prepare_shared_memory_unlink(
        &self,
        name: &[u8],
    ) -> Result<PreparedNamespace, ClientError<T::Error>> {
        let mut payload = [0; wire::NAME_HEADER_LEN + wire::MAX_NAME_BYTES + 1];
        let length = wire::encode_name(name, &mut payload).map_err(ClientError::Protocol)?;
        self.prepare_shared_memory_namespace(
            protocol::OP_SHARED_MEMORY_UNLINK,
            &payload[..length],
            None,
        )
    }

    fn prepare_shared_memory_namespace(
        &self,
        opcode: u16,
        payload: &[u8],
        rights: Option<u64>,
    ) -> Result<PreparedNamespace, ClientError<T::Error>> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let mut frame =
            [0; protocol::HEADER_LEN + wire::OPEN_HEADER_LEN + wire::MAX_NAME_BYTES + 1];
        let length = protocol::encode(
            protocol::Header {
                opcode,
                request_id,
                flags: 0,
                payload_len: payload.len() as u32,
                status: 0,
            },
            payload,
            &mut frame,
        )
        .map_err(ClientError::Protocol)?;
        Ok(PreparedNamespace {
            frame,
            length,
            request_id,
            rights,
        })
    }

    pub fn prepare_shared_memory_backing(
        &self,
        descriptor: ObjectHandleAttachment<T::Handle>,
        writable: bool,
    ) -> Result<PreparedBacking<T::Handle>, ClientError<T::Error>> {
        let required = mnu_abi::HANDLE_RIGHT_READ
            | mnu_abi::HANDLE_RIGHT_CONTROL
            | mnu_abi::HANDLE_RIGHT_TRANSFER
            | if writable {
                mnu_abi::HANDLE_RIGHT_WRITE
            } else {
                0
            };
        if descriptor.handle == T::Handle::default() || descriptor.rights & required != required {
            return Err(ClientError::Remote(-13));
        }
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let mut frame = [0; protocol::HEADER_LEN + 4];
        protocol::encode(
            protocol::Header {
                opcode: protocol::OP_SHARED_MEMORY_BACKING,
                request_id,
                flags: 0,
                payload_len: 4,
                status: 0,
            },
            &u32::from(writable).to_le_bytes(),
            &mut frame,
        )
        .map_err(ClientError::Protocol)?;
        Ok(PreparedBacking {
            frame,
            request_id,
            descriptor: ObjectHandleAttachment {
                handle: descriptor.handle,
                rights: required,
            },
            rights: wire::mapping_rights(writable),
        })
    }

    /// Borrow an explicitly attached descriptor and receive a new attenuated
    /// RAM Handle for native mapping. The returned Handle must be closed after
    /// MemoryMap; the mapping retains its own backing reference.
    /// Failed replies close distinct newly received Handles, never the borrowed
    /// descriptor, and do not replay the operation.
    pub fn shared_memory_backing(
        &self,
        descriptor: ObjectHandleAttachment<T::Handle>,
        writable: bool,
        mut close: impl FnMut(T::Handle),
    ) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
        let prepared = self.prepare_shared_memory_backing(descriptor, writable)?;
        let mut handles = ObjectHandles::new();
        handles
            .push(prepared.descriptor())
            .map_err(|_| ClientError::RequestTooLarge)?;
        let borrowed = handles.clone();
        let mut response = [0; protocol::HEADER_LEN + 1];
        let outcome = self
            .transport
            .call_with_handles(prepared.request(), &mut response, &mut handles)
            .map_err(ClientError::Transport)
            .and_then(|length| {
                let response = response
                    .get(..length)
                    .ok_or(ClientError::ResponseTooLarge)?;
                prepared.validate(response, &handles)
            });
        if outcome.is_ok() {
            return outcome;
        }
        drain_received_handles(&mut handles, &borrowed, &mut close);
        outcome
    }

    /// Returns ownership of one valid receiver-local Handle. `close` releases
    /// distinct owned unexpected attachments, including failed replies.
    pub fn open_shared_memory(
        &self,
        request: wire::Open<'_>,
        close: impl FnMut(T::Handle),
    ) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
        let prepared = self.prepare_shared_memory_open(request)?;
        self.execute_shared_memory_namespace(&prepared, close)?
            .ok_or(ClientError::MismatchedResponse)
    }

    pub fn unlink_shared_memory(
        &self,
        name: &[u8],
        close: impl FnMut(T::Handle),
    ) -> Result<(), ClientError<T::Error>> {
        let prepared = self.prepare_shared_memory_unlink(name)?;
        self.execute_shared_memory_namespace(&prepared, close)
            .map(|_| ())
    }

    fn execute_shared_memory_namespace(
        &self,
        prepared: &PreparedNamespace,
        mut close: impl FnMut(T::Handle),
    ) -> Result<Option<ObjectHandleAttachment<T::Handle>>, ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        let mut response = [0; protocol::HEADER_LEN + 1];
        let outcome = self
            .transport
            .call_with_handles(prepared.request(), &mut response, &mut handles)
            .map_err(ClientError::Transport)
            .and_then(|length| {
                let response = response
                    .get(..length)
                    .ok_or(ClientError::ResponseTooLarge)?;
                prepared.validate(response, &handles)
            });
        if outcome.is_err() {
            drain_received_handles(&mut handles, &ObjectHandles::new(), &mut close);
        }
        outcome
    }
}
