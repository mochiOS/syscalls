#![no_std]

extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};

use mochios_posix_protocol as protocol;

pub mod fd;

pub trait Transport {
    type Error;

    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, Self::Error>;
}

pub const MAX_OBJECT_HANDLES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectHandleAttachment<H> {
    pub handle: H,
    pub rights: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectHandles<H> {
    entries: [Option<ObjectHandleAttachment<H>>; MAX_OBJECT_HANDLES],
    count: usize,
}

impl<H: Copy> ObjectHandles<H> {
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_OBJECT_HANDLES],
            count: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn get(&self, index: usize) -> Option<ObjectHandleAttachment<H>> {
        (index < self.count).then(|| self.entries[index]).flatten()
    }

    pub fn push(&mut self, attachment: ObjectHandleAttachment<H>) -> Result<(), ()> {
        if self.count == MAX_OBJECT_HANDLES {
            return Err(());
        }
        self.entries[self.count] = Some(attachment);
        self.count += 1;
        Ok(())
    }

    pub fn clear(&mut self) {
        self.entries.fill(None);
        self.count = 0;
    }

    pub fn iter(&self) -> impl Iterator<Item = ObjectHandleAttachment<H>> + '_ {
        self.entries[..self.count].iter().filter_map(|entry| *entry)
    }
}

impl<H: Copy> Default for ObjectHandles<H> {
    fn default() -> Self {
        Self::new()
    }
}

pub trait ObjectTransport: Transport {
    type Handle: Copy;

    /// Performs one request while replacing outgoing attachments with the
    /// receiver-local handles attached to the response.
    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<Self::Handle>,
    ) -> Result<usize, Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenAtBase<H> {
    ProcessRoot,
    ProcessCwd,
    Directory(ObjectHandleAttachment<H>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatAtBase<H> {
    ProcessRoot,
    ProcessCwd,
    Directory(ObjectHandleAttachment<H>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientError<E> {
    Transport(E),
    Protocol(protocol::ProtocolError),
    RequestTooLarge,
    ResponseTooLarge,
    MismatchedResponse,
    Remote(i32),
}

pub struct Client<T> {
    transport: T,
    next_request_id: AtomicU64,
}

impl<T: Transport> Client<T> {
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            next_request_id: AtomicU64::new(1),
        }
    }

    pub fn ping(&self) -> Result<(), ClientError<T::Error>> {
        let mut response = [];
        self.request(protocol::OP_PING, 0, &[], &mut response)
            .map(|_| ())
    }

    /// Registers the calling process using the peer identity authenticated by
    /// the IPC transport. No PID or credentials are supplied by the client.
    pub fn register_session(&self) -> Result<(), ClientError<T::Error>> {
        let mut response = [];
        self.request(protocol::OP_SESSION_REGISTER, 0, &[], &mut response)
            .map(|_| ())
    }

    pub fn session_info(&self) -> Result<protocol::SessionInfo, ClientError<T::Error>> {
        let mut response = [0u8; protocol::SESSION_INFO_LEN];
        let length = self.request(protocol::OP_SESSION_INFO, 0, &[], &mut response)?;
        protocol::decode_session_info(&response[..length]).map_err(ClientError::Protocol)
    }

    /// Updates the process umask and returns its previous value, matching the
    /// atomic state transition required by POSIX `umask()`.
    pub fn set_umask(&self, mask: u32) -> Result<u32, ClientError<T::Error>> {
        let mut request = [0u8; protocol::UMASK_PAYLOAD_LEN];
        protocol::encode_umask(mask, &mut request).map_err(ClientError::Protocol)?;
        let mut response = [0u8; protocol::UMASK_PAYLOAD_LEN];
        let length = self.request(protocol::OP_UMASK_SET, 0, &request, &mut response)?;
        protocol::decode_umask(&response[..length]).map_err(ClientError::Protocol)
    }

    pub fn request(
        &self,
        opcode: u16,
        flags: u32,
        payload: &[u8],
        response_payload: &mut [u8],
    ) -> Result<usize, ClientError<T::Error>> {
        if payload.len() > protocol::MAX_CONTROL_PAYLOAD_LEN {
            return Err(ClientError::RequestTooLarge);
        }
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let mut request_bytes = [0u8; protocol::CONTROL_MESSAGE_LEN];
        let request_len = protocol::encode(
            protocol::Header {
                opcode,
                request_id,
                flags,
                payload_len: payload.len() as u32,
                status: protocol::STATUS_OK,
            },
            payload,
            &mut request_bytes,
        )
        .map_err(ClientError::Protocol)?;

        let mut response_bytes = [0u8; protocol::CONTROL_MESSAGE_LEN];
        let response_len = self
            .transport
            .call(&request_bytes[..request_len], &mut response_bytes)
            .map_err(ClientError::Transport)?;
        let response_bytes = response_bytes
            .get(..response_len)
            .ok_or(ClientError::ResponseTooLarge)?;
        let (header, payload) = protocol::decode(response_bytes).map_err(ClientError::Protocol)?;
        if header.opcode != protocol::OP_STATUS || header.request_id != request_id {
            return Err(ClientError::MismatchedResponse);
        }
        if header.status != protocol::STATUS_OK {
            return Err(ClientError::Remote(header.status));
        }
        if payload.len() > response_payload.len() {
            return Err(ClientError::ResponseTooLarge);
        }
        response_payload[..payload.len()].copy_from_slice(payload);
        Ok(payload.len())
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

impl<T: ObjectTransport> Client<T> {
    pub fn open_at(
        &self,
        base: OpenAtBase<T::Handle>,
        options: u32,
        mode: u32,
        path: &str,
    ) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
        let (base, directory) = match base {
            OpenAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
            OpenAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
            OpenAtBase::Directory(handle) => {
                (protocol::OpenBase::AttachedDirectory, Some(handle))
            }
        };
        let mut payload = [0u8; protocol::OPEN_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
        let payload_len = protocol::encode_open_at(
            protocol::OpenAtRequest {
                base,
                options,
                mode,
                path,
            },
            &mut payload,
        )
        .map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        if let Some(directory) = directory {
            handles
                .push(directory)
                .map_err(|_| ClientError::RequestTooLarge)?;
        }
        self.request_with_handles(
            protocol::OP_OPEN_AT,
            0,
            &payload[..payload_len],
            &mut [],
            &mut handles,
        )?;
        if handles.len() != 1 {
            return Err(ClientError::MismatchedResponse);
        }
        handles.get(0).ok_or(ClientError::MismatchedResponse)
    }

    pub fn stat_at(
        &self,
        base: StatAtBase<T::Handle>,
        flags: u32,
        path: &str,
    ) -> Result<protocol::FileStatus, ClientError<T::Error>> {
        let (base, directory) = match base {
            StatAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
            StatAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
            StatAtBase::Directory(handle) => (protocol::OpenBase::AttachedDirectory, Some(handle)),
        };
        let mut payload = [0u8; protocol::STAT_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
        let payload_len =
            protocol::encode_stat_at(protocol::StatAtRequest { base, flags, path }, &mut payload)
                .map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        if let Some(directory) = directory {
            handles
                .push(directory)
                .map_err(|_| ClientError::RequestTooLarge)?;
        }
        let mut response = [0u8; protocol::FILE_STATUS_LEN];
        let response_len = self.request_with_handles(
            protocol::OP_STAT_AT,
            0,
            &payload[..payload_len],
            &mut response,
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        protocol::decode_file_status(&response[..response_len]).map_err(ClientError::Protocol)
    }

    pub fn fstat(
        &self,
        file: ObjectHandleAttachment<T::Handle>,
    ) -> Result<protocol::FileStatus, ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        handles
            .push(file)
            .map_err(|_| ClientError::RequestTooLarge)?;
        let mut response = [0u8; protocol::FILE_STATUS_LEN];
        let response_len =
            self.request_with_handles(protocol::OP_FSTAT, 0, &[], &mut response, &mut handles)?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        protocol::decode_file_status(&response[..response_len]).map_err(ClientError::Protocol)
    }

    pub fn request_with_handles(
        &self,
        opcode: u16,
        flags: u32,
        payload: &[u8],
        response_payload: &mut [u8],
        handles: &mut ObjectHandles<T::Handle>,
    ) -> Result<usize, ClientError<T::Error>> {
        if payload.len() > protocol::MAX_CONTROL_PAYLOAD_LEN {
            return Err(ClientError::RequestTooLarge);
        }
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let mut request_bytes = [0u8; protocol::CONTROL_MESSAGE_LEN];
        let request_len = protocol::encode(
            protocol::Header {
                opcode,
                request_id,
                flags,
                payload_len: payload.len() as u32,
                status: protocol::STATUS_OK,
            },
            payload,
            &mut request_bytes,
        )
        .map_err(ClientError::Protocol)?;

        let mut response_bytes = [0u8; protocol::CONTROL_MESSAGE_LEN];
        let response_len = self
            .transport
            .call_with_handles(
                &request_bytes[..request_len],
                &mut response_bytes,
                handles,
            )
            .map_err(ClientError::Transport)?;
        let response_bytes = response_bytes
            .get(..response_len)
            .ok_or(ClientError::ResponseTooLarge)?;
        let (header, payload) = protocol::decode(response_bytes).map_err(ClientError::Protocol)?;
        if header.opcode != protocol::OP_STATUS || header.request_id != request_id {
            return Err(ClientError::MismatchedResponse);
        }
        if header.status != protocol::STATUS_OK {
            return Err(ClientError::Remote(header.status));
        }
        if payload.len() > response_payload.len() {
            return Err(ClientError::ResponseTooLarge);
        }
        response_payload[..payload.len()].copy_from_slice(payload);
        Ok(payload.len())
    }
}

#[cfg(feature = "endpoint")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointTransport {
    endpoint: mochi_user_platform::handle::Handle,
}

#[cfg(feature = "endpoint")]
impl EndpointTransport {
    pub const fn new(endpoint: mochi_user_platform::handle::Handle) -> Self {
        Self { endpoint }
    }

    pub fn from_launch_context() -> Result<Self, mochi_user_platform::syscall::SysError> {
        mochi_user_platform::handle::inherited(protocol::CONTROL_HANDLE_KEY).map(Self::new)
    }

    pub const fn endpoint(self) -> mochi_user_platform::handle::Handle {
        self.endpoint
    }
}

#[cfg(feature = "endpoint")]
impl Client<EndpointTransport> {
    /// Connects to the inherited POSIX endpoint and registers this process's
    /// authenticated session before returning it to libc/runtime code.
    pub fn from_launch_context() -> Result<Self, ClientError<mochi_user_platform::syscall::SysError>>
    {
        let transport = EndpointTransport::from_launch_context().map_err(ClientError::Transport)?;
        let client = Self::new(transport);
        client.register_session()?;
        Ok(client)
    }
}

#[cfg(feature = "endpoint")]
impl Transport for EndpointTransport {
    type Error = mochi_user_platform::syscall::SysError;

    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, Self::Error> {
        let received = mochi_user_platform::ipc::call(self.endpoint as u64, request, response)?;
        let length = (received & 0xffff_ffff) as usize;
        if length > response.len() {
            return Err(mochi_user_platform::syscall::SysError::from_raw(
                mochi_user_platform::syscall::EOVERFLOW as i64,
            ));
        }
        Ok(length)
    }
}

#[cfg(feature = "endpoint")]
impl ObjectTransport for EndpointTransport {
    type Handle = mochi_user_platform::handle::Handle;

    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<Self::Handle>,
    ) -> Result<usize, Self::Error> {
        let mut native = mochi_user_platform::ipc::IpcObjectHandles::default();
        native.count = handles.len() as u32;
        for (index, attachment) in handles.iter().enumerate() {
            native.handles[index].handle = attachment.handle;
            native.handles[index].rights = attachment.rights;
        }
        let received = mochi_user_platform::ipc::call_object_handles(
            self.endpoint,
            request,
            response,
            &mut native,
        )?;
        let count = usize::try_from(native.count).map_err(|_| {
            mochi_user_platform::syscall::SysError::from_raw(
                mochi_user_platform::syscall::EOVERFLOW as i64,
            )
        })?;
        if count > MAX_OBJECT_HANDLES || native.reserved != 0 {
            for attachment in native.handles.iter().take(count.min(MAX_OBJECT_HANDLES)) {
                if attachment.handle != 0 {
                    let _ = mochi_user_platform::handle::close(attachment.handle);
                }
            }
            return Err(mochi_user_platform::syscall::SysError::from_raw(
                mochi_user_platform::syscall::EINVAL as i64,
            ));
        }
        for attachment in native.handles.iter().take(count) {
            if attachment.handle == 0 || attachment.reserved != 0 {
                for received in native.handles.iter().take(count) {
                    if received.handle != 0 {
                        let _ = mochi_user_platform::handle::close(received.handle);
                    }
                }
                return Err(mochi_user_platform::syscall::SysError::from_raw(
                    mochi_user_platform::syscall::EINVAL as i64,
                ));
            }
        }
        handles.clear();
        for attachment in native.handles.iter().take(count) {
            handles
                .push(ObjectHandleAttachment {
                    handle: attachment.handle,
                    rights: attachment.rights,
                })
                .map_err(|_| {
                    mochi_user_platform::syscall::SysError::from_raw(
                        mochi_user_platform::syscall::EOVERFLOW as i64,
                    )
                })?;
        }
        let length = (received & 0xffff_ffff) as usize;
        if length > response.len() {
            return Err(mochi_user_platform::syscall::SysError::from_raw(
                mochi_user_platform::syscall::EOVERFLOW as i64,
            ));
        }
        Ok(length)
    }
}

/// Native fast-path backend for descriptors that already contain an object
/// handle. No request is sent to `posix.service` for these operations.
#[cfg(feature = "endpoint")]
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeFileOps;

#[cfg(feature = "endpoint")]
impl fd::HandleOps<mochi_user_platform::handle::Handle> for NativeFileOps {
    type Error = mochi_user_platform::syscall::SysError;

    fn clone_handle(
        &mut self,
        handle: mochi_user_platform::handle::Handle,
        rights: u64,
    ) -> Result<mochi_user_platform::handle::Handle, Self::Error> {
        mochi_user_platform::handle::duplicate(handle, rights)
    }

    fn close_handle(&mut self, handle: mochi_user_platform::handle::Handle) {
        let _ = mochi_user_platform::handle::close(handle);
    }
}

#[cfg(feature = "endpoint")]
impl fd::FileOps<mochi_user_platform::handle::Handle> for NativeFileOps {
    type Error = mochi_user_platform::syscall::SysError;

    fn read(
        &mut self,
        handle: mochi_user_platform::handle::Handle,
        buffer: &mut [u8],
    ) -> Result<usize, Self::Error> {
        mochi_user_platform::handle::read(handle, buffer)
    }

    fn write(
        &mut self,
        handle: mochi_user_platform::handle::Handle,
        buffer: &[u8],
    ) -> Result<usize, Self::Error> {
        mochi_user_platform::handle::write(handle, buffer)
    }

    fn seek(
        &mut self,
        handle: mochi_user_platform::handle::Handle,
        offset: i64,
        basis: fd::SeekBasis,
    ) -> Result<u64, Self::Error> {
        let basis = match basis {
            fd::SeekBasis::Start => mochi_user_platform::handle::HANDLE_SEEK_START,
            fd::SeekBasis::Current => mochi_user_platform::handle::HANDLE_SEEK_CURRENT,
            fd::SeekBasis::End => mochi_user_platform::handle::HANDLE_SEEK_END,
        };
        mochi_user_platform::handle::seek(handle, offset, basis)
    }
}
