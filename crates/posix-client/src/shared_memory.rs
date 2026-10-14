//! Named RAM control operations; mapped data and extent changes use native
//! Handle operations without routing frequent accesses through the service.

use crate::{Client, ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport};
use mochios_posix_protocol::{self as protocol, shared_memory as wire};

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
    /// Borrow an explicitly attached descriptor and receive a new attenuated
    /// RAM Handle for native mapping. The returned Handle must be closed after
    /// MemoryMap; the mapping retains its own backing reference.
    pub fn shared_memory_backing(
        &self,
        descriptor: ObjectHandleAttachment<T::Handle>,
        writable: bool,
        mut close: impl FnMut(T::Handle),
    ) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
        let required = mnu_abi::HANDLE_RIGHT_READ
            | mnu_abi::HANDLE_RIGHT_CONTROL
            | mnu_abi::HANDLE_RIGHT_TRANSFER
            | if writable {
                mnu_abi::HANDLE_RIGHT_WRITE
            } else {
                0
            };
        if descriptor.rights & required != required {
            return Err(ClientError::Remote(-13));
        }
        let mut handles = ObjectHandles::new();
        handles
            .push(ObjectHandleAttachment {
                handle: descriptor.handle,
                rights: required,
            })
            .map_err(|_| ClientError::RequestTooLarge)?;
        let outcome = self.request_with_handles(
            protocol::OP_SHARED_MEMORY_BACKING,
            0,
            &u32::from(writable).to_le_bytes(),
            &mut [],
            &mut handles,
        );
        if matches!(outcome, Ok(0)) && handles.len() == 1 {
            let received = handles.get(0).unwrap();
            if received.rights == wire::mapping_rights(writable) {
                return Ok(received);
            }
        }
        for received in handles.iter() {
            close(received.handle);
        }
        Err(outcome.err().unwrap_or(ClientError::MismatchedResponse))
    }

    /// Returns ownership of one receiver-local Handle. `close` releases every
    /// unexpected attachment, including malformed or unsuccessful replies.
    pub fn open_shared_memory(
        &self,
        request: wire::Open<'_>,
        mut close: impl FnMut(T::Handle),
    ) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
        let mut payload = [0; wire::OPEN_HEADER_LEN + wire::MAX_NAME_BYTES + 1];
        let length = wire::encode_open(request, &mut payload).map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        let outcome = self.request_with_handles(
            protocol::OP_SHARED_MEMORY_OPEN,
            0,
            &payload[..length],
            &mut [],
            &mut handles,
        );
        if matches!(outcome, Ok(0)) && handles.len() == 1 {
            let received = handles.get(0).unwrap();
            if received.rights == rights(request.options & wire::READ_WRITE != 0) {
                return Ok(received);
            }
        }
        for received in handles.iter() {
            close(received.handle);
        }
        Err(outcome.err().unwrap_or(ClientError::MismatchedResponse))
    }

    pub fn unlink_shared_memory(
        &self,
        name: &[u8],
        mut close: impl FnMut(T::Handle),
    ) -> Result<(), ClientError<T::Error>> {
        let mut payload = [0; wire::NAME_HEADER_LEN + wire::MAX_NAME_BYTES + 1];
        let length = wire::encode_name(name, &mut payload).map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        let outcome = self.request_with_handles(
            protocol::OP_SHARED_MEMORY_UNLINK,
            0,
            &payload[..length],
            &mut [],
            &mut handles,
        );
        if matches!(outcome, Ok(0)) && handles.is_empty() {
            return Ok(());
        }
        for received in handles.iter() {
            close(received.handle);
        }
        Err(outcome.err().unwrap_or(ClientError::MismatchedResponse))
    }
}
