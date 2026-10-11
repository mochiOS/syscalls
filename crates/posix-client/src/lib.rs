#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};

use mochios_posix_protocol as protocol;

pub mod configuration;
pub mod directory;
pub mod io_vector;
#[cfg(feature = "fd-table")]
pub mod fd;
pub mod memory;
pub mod multiplex;
pub mod newlib_errno;
pub mod process_image;
pub mod random;
pub mod signal;
pub mod spawn;
pub mod stream;
#[cfg(feature = "syscall-endpoint")]
pub mod synchronization;
pub mod thread;
pub mod time;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PtyPair<H> {
    pub master: ObjectHandleAttachment<H>,
    pub slave: ObjectHandleAttachment<H>,
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
pub enum AccessAtBase<H> {
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

    pub fn wait_child(
        &self,
        selector: i64,
        options: u32,
    ) -> Result<protocol::WaitResult, ClientError<T::Error>> {
        let mut request = [0u8; protocol::WAIT_REQUEST_LEN];
        protocol::encode_wait_request(protocol::WaitRequest { selector, options }, &mut request)
            .map_err(ClientError::Protocol)?;
        let mut response = [0u8; protocol::WAIT_RESULT_LEN];
        let length = self.request(protocol::OP_WAIT_CHILD, 0, &request, &mut response)?;
        protocol::decode_wait_result(&response[..length]).map_err(ClientError::Protocol)
    }

    /// Reports a default job-control stop for the authenticated calling
    /// process. The request intentionally carries no process identifier.
    pub fn report_process_stopped(
        &self,
        delivery: protocol::SignalDelivery,
    ) -> Result<(), ClientError<T::Error>> {
        self.signal_delivery_request(protocol::OP_PROCESS_STOPPED, delivery)
    }

    /// Completes a signal delivery which did not change process lifecycle.
    pub fn complete_signal_delivery(
        &self,
        delivery: protocol::SignalDelivery,
    ) -> Result<(), ClientError<T::Error>> {
        self.signal_delivery_request(protocol::OP_SIGNAL_DELIVERY_COMPLETE, delivery)
    }

    /// Applies the default terminating action to the authenticated calling
    /// process. The request contains no process identifier.
    pub fn report_process_signaled(
        &self,
        delivery: protocol::SignalDelivery,
    ) -> Result<(), ClientError<T::Error>> {
        self.signal_delivery_request(protocol::OP_PROCESS_SIGNALED, delivery)
    }

    fn signal_delivery_request(
        &self,
        opcode: u16,
        delivery: protocol::SignalDelivery,
    ) -> Result<(), ClientError<T::Error>> {
        let mut request = [0u8; protocol::SIGNAL_DELIVERY_LEN];
        protocol::encode_signal_delivery(delivery, &mut request).map_err(ClientError::Protocol)?;
        self.request(opcode, 0, &request, &mut []).map(|_| ())
    }

    pub fn process_info(
        &self,
        process_id: i64,
    ) -> Result<protocol::ProcessInfo, ClientError<T::Error>> {
        let mut request = [0u8; protocol::PROCESS_ID_REQUEST_LEN];
        protocol::encode_process_id_request(process_id, &mut request)
            .map_err(ClientError::Protocol)?;
        let mut response = [0u8; protocol::PROCESS_INFO_LEN];
        let length = self.request(protocol::OP_PROCESS_INFO, 0, &request, &mut response)?;
        protocol::decode_process_info(&response[..length]).map_err(ClientError::Protocol)
    }

    pub fn set_process_group(
        &self,
        process_id: i64,
        process_group_id: i64,
    ) -> Result<(), ClientError<T::Error>> {
        let mut request = [0u8; protocol::PROCESS_GROUP_REQUEST_LEN];
        protocol::encode_process_group_request(process_id, process_group_id, &mut request)
            .map_err(ClientError::Protocol)?;
        self.request(protocol::OP_SET_PROCESS_GROUP, 0, &request, &mut [])
            .map(|_| ())
    }

    pub fn create_session(&self) -> Result<u64, ClientError<T::Error>> {
        let mut response = [0u8; protocol::PROCESS_INFO_LEN];
        let length = self.request(protocol::OP_CREATE_SESSION, 0, &[], &mut response)?;
        protocol::decode_process_info(&response[..length])
            .map(|info| info.session_id)
            .map_err(ClientError::Protocol)
    }

    pub fn send_signal(&self, selector: i64, signal: u32) -> Result<(), ClientError<T::Error>> {
        let mut request = [0u8; protocol::SIGNAL_SEND_REQUEST_LEN];
        protocol::encode_signal_send_request(
            protocol::SignalSendRequest { selector, signal },
            &mut request,
        )
        .map_err(ClientError::Protocol)?;
        self.request(protocol::OP_SIGNAL_SEND, 0, &request, &mut [])
            .map(|_| ())
    }

    pub fn pending_signals(&self) -> Result<u64, ClientError<T::Error>> {
        let mut response = [0u8; protocol::SIGNAL_MASK_LEN];
        let length = self.request(protocol::OP_SIGNAL_PENDING, 0, &[], &mut response)?;
        protocol::decode_signal_mask(&response[..length]).map_err(ClientError::Protocol)
    }

    pub fn set_signal_child_options(
        &self,
        options: u32,
    ) -> Result<(), ClientError<T::Error>> {
        let mut request = [0u8; protocol::SIGNAL_CHILD_OPTIONS_LEN];
        protocol::encode_signal_child_options(options, &mut request)
            .map_err(ClientError::Protocol)?;
        self.request(protocol::OP_SIGNAL_CHILD_OPTIONS, 0, &request, &mut [])
            .map(|_| ())
    }

    /// Atomically removes the lowest-numbered pending signal that is not in
    /// `blocked`. Zero means that no signal is currently deliverable.
    pub fn dequeue_signal(&self, blocked: u64) -> Result<u32, ClientError<T::Error>> {
        let delivery = self.dequeue_signal_delivery(blocked)?;
        if delivery.signal != 0 {
            self.complete_signal_delivery(delivery)?;
        }
        Ok(delivery.signal)
    }

    pub fn dequeue_signal_delivery(
        &self,
        blocked: u64,
    ) -> Result<protocol::SignalDelivery, ClientError<T::Error>> {
        let mut request = [0u8; protocol::SIGNAL_MASK_LEN];
        protocol::encode_signal_mask(blocked, &mut request).map_err(ClientError::Protocol)?;
        let mut response = [0u8; protocol::SIGNAL_DELIVERY_LEN];
        let length = self.request(protocol::OP_SIGNAL_DEQUEUE, 0, &request, &mut response)?;
        protocol::decode_signal_delivery(&response[..length]).map_err(ClientError::Protocol)
    }

    /// Reads a resource limit and optionally replaces it atomically. A
    /// process ID of zero selects the calling process. The returned value is
    /// always the limit that was installed before this request.
    pub fn resource_limit(
        &self,
        process_id: i64,
        resource: u32,
        replacement: Option<protocol::ResourceLimit>,
    ) -> Result<protocol::ResourceLimit, ClientError<T::Error>> {
        let mut request = [0u8; protocol::RESOURCE_LIMIT_REQUEST_LEN];
        protocol::encode_resource_limit_request(
            protocol::ResourceLimitRequest {
                process_id,
                resource,
                flags: if replacement.is_some() {
                    protocol::RESOURCE_LIMIT_SET
                } else {
                    0
                },
                limit: replacement.unwrap_or_default(),
            },
            &mut request,
        )
        .map_err(ClientError::Protocol)?;
        let mut response = [0u8; protocol::RESOURCE_LIMIT_LEN];
        let length = self.request(protocol::OP_RESOURCE_LIMIT, 0, &request, &mut response)?;
        protocol::decode_resource_limit(&response[..length]).map_err(ClientError::Protocol)
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

    pub fn set_uid(&self, uid: u32) -> Result<(), ClientError<T::Error>> {
        self.set_credential_id(protocol::OP_SET_UID, uid)
    }

    pub fn set_gid(&self, gid: u32) -> Result<(), ClientError<T::Error>> {
        self.set_credential_id(protocol::OP_SET_GID, gid)
    }

    pub fn set_effective_uid(&self, uid: u32) -> Result<(), ClientError<T::Error>> {
        self.set_credential_id(protocol::OP_SET_EFFECTIVE_UID, uid)
    }

    pub fn set_effective_gid(&self, gid: u32) -> Result<(), ClientError<T::Error>> {
        self.set_credential_id(protocol::OP_SET_EFFECTIVE_GID, gid)
    }

    /// Atomically updates IDs and the saved ID according to `setreuid`.
    /// `CREDENTIAL_ID_UNCHANGED` leaves the corresponding ID unchanged.
    pub fn set_real_effective_uid(
        &self,
        real: u32,
        effective: u32,
    ) -> Result<(), ClientError<T::Error>> {
        self.set_credential_pair(protocol::OP_SET_REAL_EFFECTIVE_UID, real, effective)
    }

    /// Atomically updates IDs and the saved ID according to `setregid`.
    pub fn set_real_effective_gid(
        &self,
        real: u32,
        effective: u32,
    ) -> Result<(), ClientError<T::Error>> {
        self.set_credential_pair(protocol::OP_SET_REAL_EFFECTIVE_GID, real, effective)
    }

    fn set_credential_pair(
        &self,
        opcode: u16,
        real: u32,
        effective: u32,
    ) -> Result<(), ClientError<T::Error>> {
        let mut request = [0; protocol::CREDENTIAL_PAIR_PAYLOAD_LEN];
        protocol::encode_credential_pair(real, effective, &mut request)
            .map_err(ClientError::Protocol)?;
        self.request(opcode, 0, &request, &mut []).map(|_| ())
    }

    /// Atomically restores the effective UID and GID from the calling
    /// process's real IDs, as required by `POSIX_SPAWN_RESETIDS`.
    pub fn reset_effective_ids(&self) -> Result<(), ClientError<T::Error>> {
        self.request(protocol::OP_RESET_EFFECTIVE_IDS, 0, &[], &mut [])
            .map(|_| ())
    }

    /// Returns the calling process's supplementary groups.
    pub fn get_groups(&self, output: &mut [u32]) -> Result<usize, ClientError<T::Error>> {
        let mut response = [0u8; protocol::GROUP_LIST_MAX_LEN];
        let length = self.request(protocol::OP_GROUPS_GET, 0, &[], &mut response)?;
        protocol::decode_group_list(&response[..length], output).map_err(ClientError::Protocol)
    }

    /// Replaces the calling process's supplementary groups atomically.
    pub fn set_groups(&self, groups: &[u32]) -> Result<(), ClientError<T::Error>> {
        let mut request = [0u8; protocol::GROUP_LIST_MAX_LEN];
        let length =
            protocol::encode_group_list(groups, &mut request).map_err(ClientError::Protocol)?;
        self.request(protocol::OP_GROUPS_SET, 0, &request[..length], &mut [])
            .map(|_| ())
    }

    fn set_credential_id(&self, opcode: u16, id: u32) -> Result<(), ClientError<T::Error>> {
        let mut request = [0u8; protocol::CREDENTIAL_ID_PAYLOAD_LEN];
        protocol::encode_credential_id(id, &mut request).map_err(ClientError::Protocol)?;
        self.request(opcode, 0, &request, &mut []).map(|_| ())
    }

    /// Writes the current working directory without a trailing NUL and
    /// returns the number of bytes written.
    pub fn getcwd(&self, output: &mut [u8]) -> Result<usize, ClientError<T::Error>> {
        self.request(protocol::OP_GETCWD, 0, &[], output)
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

    /// Borrow the caller-owned transport without transferring its Handle.
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: ObjectTransport> Client<T> {
    pub fn open_pty(&self) -> Result<PtyPair<T::Handle>, ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        self.request_with_handles(protocol::OP_PTY_OPEN, 0, &[], &mut [], &mut handles)?;
        if handles.len() != 2 {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(PtyPair {
            master: handles.get(0).ok_or(ClientError::MismatchedResponse)?,
            slave: handles.get(1).ok_or(ClientError::MismatchedResponse)?,
        })
    }

    pub fn acquire_controlling_terminal(
        &self,
        terminal: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        self.terminal_request(protocol::OP_TERMINAL_ACQUIRE, &[], terminal, &mut [])
            .map(|_| ())
    }

    pub fn release_controlling_terminal(
        &self,
        terminal: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        self.terminal_request(protocol::OP_TERMINAL_RELEASE, &[], terminal, &mut [])
            .map(|_| ())
    }

    pub fn terminal_foreground_process_group(
        &self,
        terminal: ObjectHandleAttachment<T::Handle>,
    ) -> Result<u64, ClientError<T::Error>> {
        let mut response = [0u8; protocol::PROCESS_ID_REQUEST_LEN];
        let length = self.terminal_request(
            protocol::OP_TERMINAL_GET_FOREGROUND,
            &[],
            terminal,
            &mut response,
        )?;
        let group = protocol::decode_process_id_request(&response[..length])
            .map_err(ClientError::Protocol)?;
        u64::try_from(group)
            .ok()
            .filter(|group| *group != 0)
            .ok_or(ClientError::MismatchedResponse)
    }

    pub fn set_terminal_foreground_process_group(
        &self,
        terminal: ObjectHandleAttachment<T::Handle>,
        process_group: u64,
    ) -> Result<(), ClientError<T::Error>> {
        let process_group = i64::try_from(process_group)
            .ok()
            .filter(|group| *group != 0)
            .ok_or(ClientError::RequestTooLarge)?;
        let mut payload = [0u8; protocol::PROCESS_ID_REQUEST_LEN];
        protocol::encode_process_id_request(process_group, &mut payload)
            .map_err(ClientError::Protocol)?;
        self.terminal_request(
            protocol::OP_TERMINAL_SET_FOREGROUND,
            &payload,
            terminal,
            &mut [],
        )
        .map(|_| ())
    }

    fn terminal_request(
        &self,
        opcode: u16,
        payload: &[u8],
        terminal: ObjectHandleAttachment<T::Handle>,
        response: &mut [u8],
    ) -> Result<usize, ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        handles
            .push(terminal)
            .map_err(|_| ClientError::RequestTooLarge)?;
        let length = self.request_with_handles(opcode, 0, payload, response, &mut handles)?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(length)
    }

    pub fn register_signal_thread(
        &self,
        thread: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        handles
            .push(thread)
            .map_err(|_| ClientError::RequestTooLarge)?;
        self.request_with_handles(
            protocol::OP_SIGNAL_THREAD_REGISTER,
            0,
            &[],
            &mut [],
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    /// Registers a freshly cloned process as a POSIX child. Identity is
    /// derived from the attached ProcessHandle, never from request bytes.
    pub fn register_child(
        &self,
        process: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        handles
            .push(process)
            .map_err(|_| ClientError::RequestTooLarge)?;
        self.request_with_handles(protocol::OP_PROCESS_FORKED, 0, &[], &mut [], &mut handles)?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    /// Initializes a running boot process through an explicit ProcessHandle.
    /// Only the inherited userspace bootstrap authority may make this request.
    pub fn initialize_process(
        &self,
        process: ObjectHandleAttachment<T::Handle>,
        uid: u32,
        gid: u32,
        groups: &[u32],
    ) -> Result<(), ClientError<T::Error>> {
        let mut payload = [0; 8 + protocol::GROUP_LIST_MAX_LEN];
        let length = protocol::encode_spawn_credentials(uid, gid, groups, &mut payload)
            .map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        handles
            .push(process)
            .map_err(|_| ClientError::RequestTooLarge)?;
        self.request_with_handles(
            protocol::OP_PROCESS_INITIALIZE,
            0,
            &payload[..length],
            &mut [],
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    /// Registers fresh-image POSIX state before the creator resumes the child.
    pub fn register_spawned_child(
        &self,
        process: ObjectHandleAttachment<T::Handle>,
        uid: u32,
        gid: u32,
        groups: &[u32],
    ) -> Result<(), ClientError<T::Error>> {
        let mut payload = [0; 8 + protocol::GROUP_LIST_MAX_LEN];
        let length = protocol::encode_spawn_credentials(uid, gid, groups, &mut payload)
            .map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        handles
            .push(process)
            .map_err(|_| ClientError::RequestTooLarge)?;
        self.request_with_handles(
            protocol::OP_PROCESS_SPAWNED,
            0,
            &payload[..length],
            &mut [],
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    /// Registers a broker-created image as the requester's POSIX child. Both
    /// identities come from explicit ProcessHandle attachments, not PID bytes.
    /// The broker must have userspace POSIX initialization authority; possession
    /// of these handles never creates or expands native capabilities.
    pub fn register_launched_child(
        &self,
        requester: ObjectHandleAttachment<T::Handle>,
        child: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        handles
            .push(requester)
            .map_err(|_| ClientError::RequestTooLarge)?;
        handles
            .push(child)
            .map_err(|_| ClientError::RequestTooLarge)?;
        self.request_with_handles(protocol::OP_PROCESS_LAUNCHED, 0, &[], &mut [], &mut handles)?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    /// Terminates and reclaims a failed fork or launch registered by this creator.
    /// The child's PID is authenticated from the explicit ProcessHandle.
    /// Retry after transport failure while retaining the native process owner.
    /// ESRCH is completed cleanup only when that owner confirms native exit.
    pub fn abort_launched_child(
        &self,
        child: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        handles
            .push(child)
            .map_err(|_| ClientError::RequestTooLarge)?;
        self.request_with_handles(
            protocol::OP_PROCESS_LAUNCH_ABORT,
            0,
            &[],
            &mut [],
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    /// Terminates a tree registered by this launcher, using its explicit root
    /// ProcessHandle with WAIT|SIGNAL rights. No PID or credentials are sent.
    /// Delayed exits return EAGAIN; callers must retain their root reference
    /// until successful completion and may retry the same request. Success
    /// confirms all exits, but retains server references until reclaim.
    pub fn terminate_launched_tree(
        &self,
        root: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        self.tree_request(protocol::OP_PROCESS_TREE_TERMINATE, root)
    }

    /// Reclaims an exited tree after a successful termination confirmation.
    /// A caller may treat ESRCH as an already completed reclaim ONLY if it
    /// previously received that confirmation for this same owned root object.
    pub fn reclaim_launched_tree(
        &self,
        root: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        self.tree_request(protocol::OP_PROCESS_TREE_RECLAIM, root)
    }

    fn tree_request(
        &self,
        opcode: u16,
        root: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        handles
            .push(root)
            .map_err(|_| ClientError::RequestTooLarge)?;
        self.request_with_handles(opcode, 0, &[], &mut [], &mut handles)?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    /// Inspects POSIX credentials through an explicitly attached WAIT-only
    /// ProcessHandle. The service authenticates the object, not a supplied PID.
    pub fn process_session_info(
        &self,
        process: ObjectHandleAttachment<T::Handle>,
    ) -> Result<protocol::SessionInfo, ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        handles
            .push(process)
            .map_err(|_| ClientError::RequestTooLarge)?;
        let mut response = [0; protocol::SESSION_INFO_LEN];
        let length = self.request_with_handles(
            protocol::OP_PROCESS_SESSION_INFO,
            0,
            &[],
            &mut response,
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        protocol::decode_session_info(&response[..length]).map_err(ClientError::Protocol)
    }

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
            OpenAtBase::Directory(handle) => (protocol::OpenBase::AttachedDirectory, Some(handle)),
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

    pub fn access_at(
        &self,
        base: AccessAtBase<T::Handle>,
        flags: u32,
        modes: u32,
        path: &str,
    ) -> Result<(), ClientError<T::Error>> {
        let (base, directory) = match base {
            AccessAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
            AccessAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
            AccessAtBase::Directory(handle) => {
                (protocol::OpenBase::AttachedDirectory, Some(handle))
            }
        };
        let mut payload = [0u8; protocol::ACCESS_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
        let payload_len = protocol::encode_access_at(
            protocol::AccessAtRequest {
                base,
                flags,
                modes,
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
            protocol::OP_ACCESS_AT,
            0,
            &payload[..payload_len],
            &mut [],
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    pub fn chdir_at(
        &self,
        base: StatAtBase<T::Handle>,
        path: &str,
    ) -> Result<(), ClientError<T::Error>> {
        let (base, directory) = match base {
            StatAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
            StatAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
            StatAtBase::Directory(handle) => (protocol::OpenBase::AttachedDirectory, Some(handle)),
        };
        let mut payload = [0u8; protocol::STAT_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
        let payload_len = protocol::encode_stat_at(
            protocol::StatAtRequest {
                base,
                flags: 0,
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
            protocol::OP_CHDIR_AT,
            0,
            &payload[..payload_len],
            &mut [],
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    pub fn chroot_at(
        &self,
        base: StatAtBase<T::Handle>,
        path: &str,
    ) -> Result<(), ClientError<T::Error>> {
        let (base, directory) = match base {
            StatAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
            StatAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
            StatAtBase::Directory(handle) => (protocol::OpenBase::AttachedDirectory, Some(handle)),
        };
        let mut payload = [0u8; protocol::STAT_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
        let payload_len = protocol::encode_stat_at(
            protocol::StatAtRequest {
                base,
                flags: 0,
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
            protocol::OP_CHROOT_AT,
            0,
            &payload[..payload_len],
            &mut [],
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    pub fn fchdir(
        &self,
        directory: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        handles
            .push(directory)
            .map_err(|_| ClientError::RequestTooLarge)?;
        self.request_with_handles(protocol::OP_FCHDIR, 0, &[], &mut [], &mut handles)?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    pub fn ftruncate(
        &self,
        file: ObjectHandleAttachment<T::Handle>,
        length: u64,
    ) -> Result<(), ClientError<T::Error>> {
        let mut payload = [0u8; protocol::FILE_LENGTH_PAYLOAD_LEN];
        protocol::encode_file_length(length, &mut payload).map_err(ClientError::Protocol)?;
        self.file_operation(protocol::OP_FTRUNCATE, &payload, file)
    }

    pub fn fsync(
        &self,
        file: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        self.file_operation(protocol::OP_FSYNC, &[], file)
    }

    pub fn get_status_flags(
        &self,
        file: ObjectHandleAttachment<T::Handle>,
    ) -> Result<u32, ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        handles
            .push(file)
            .map_err(|_| ClientError::RequestTooLarge)?;
        let mut payload = [0u8; protocol::FILE_FLAGS_PAYLOAD_LEN];
        let payload_len =
            self.request_with_handles(protocol::OP_FGETFL, 0, &[], &mut payload, &mut handles)?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        protocol::decode_file_flags(&payload[..payload_len]).map_err(ClientError::Protocol)
    }

    pub fn set_status_flags(
        &self,
        file: ObjectHandleAttachment<T::Handle>,
        flags: u32,
    ) -> Result<(), ClientError<T::Error>> {
        let mut payload = [0u8; protocol::FILE_FLAGS_PAYLOAD_LEN];
        protocol::encode_file_flags(flags, &mut payload).map_err(ClientError::Protocol)?;
        self.file_operation(protocol::OP_FSETFL, &payload, file)
    }

    pub fn mkdir_at(
        &self,
        base: OpenAtBase<T::Handle>,
        mode: u32,
        path: &str,
    ) -> Result<(), ClientError<T::Error>> {
        let (base, directory) = match base {
            OpenAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
            OpenAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
            OpenAtBase::Directory(handle) => (protocol::OpenBase::AttachedDirectory, Some(handle)),
        };
        let mut payload = [0u8; protocol::OPEN_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
        let payload_len = protocol::encode_open_at(
            protocol::OpenAtRequest {
                base,
                options: 0,
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
            protocol::OP_MKDIR_AT,
            0,
            &payload[..payload_len],
            &mut [],
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    pub fn unlink_at(
        &self,
        base: StatAtBase<T::Handle>,
        flags: u32,
        path: &str,
    ) -> Result<(), ClientError<T::Error>> {
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
        self.request_with_handles(
            protocol::OP_UNLINK_AT,
            0,
            &payload[..payload_len],
            &mut [],
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    pub fn rename_at(
        &self,
        old_base: StatAtBase<T::Handle>,
        old_path: &str,
        new_base: StatAtBase<T::Handle>,
        new_path: &str,
    ) -> Result<(), ClientError<T::Error>> {
        fn split_base<H: Copy>(
            base: StatAtBase<H>,
        ) -> (protocol::OpenBase, Option<ObjectHandleAttachment<H>>) {
            match base {
                StatAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
                StatAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
                StatAtBase::Directory(handle) => {
                    (protocol::OpenBase::AttachedDirectory, Some(handle))
                }
            }
        }
        let (old_base, old_directory) = split_base(old_base);
        let (new_base, new_directory) = split_base(new_base);
        let mut payload = [0u8; protocol::RENAME_AT_HEADER_LEN + protocol::MAX_PATH_LEN * 2];
        let payload_len = protocol::encode_rename_at(
            protocol::RenameAtRequest {
                old_base,
                new_base,
                old_path,
                new_path,
            },
            &mut payload,
        )
        .map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        for directory in [old_directory, new_directory].into_iter().flatten() {
            handles
                .push(directory)
                .map_err(|_| ClientError::RequestTooLarge)?;
        }
        self.request_with_handles(
            protocol::OP_RENAME_AT,
            0,
            &payload[..payload_len],
            &mut [],
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    pub fn link_at(
        &self,
        old_base: StatAtBase<T::Handle>,
        old_path: &str,
        new_base: StatAtBase<T::Handle>,
        new_path: &str,
        flags: u32,
    ) -> Result<(), ClientError<T::Error>> {
        fn split_base<H: Copy>(
            base: StatAtBase<H>,
        ) -> (protocol::OpenBase, Option<ObjectHandleAttachment<H>>) {
            match base {
                StatAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
                StatAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
                StatAtBase::Directory(handle) => {
                    (protocol::OpenBase::AttachedDirectory, Some(handle))
                }
            }
        }
        let (old_base, old_directory) = split_base(old_base);
        let (new_base, new_directory) = split_base(new_base);
        let mut payload = [0u8; protocol::LINK_AT_HEADER_LEN + protocol::MAX_PATH_LEN * 2];
        let payload_len = protocol::encode_link_at(
            protocol::LinkAtRequest {
                old_base,
                new_base,
                flags,
                old_path,
                new_path,
            },
            &mut payload,
        )
        .map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        for directory in [old_directory, new_directory].into_iter().flatten() {
            handles
                .push(directory)
                .map_err(|_| ClientError::RequestTooLarge)?;
        }
        self.request_with_handles(
            protocol::OP_LINK_AT,
            0,
            &payload[..payload_len],
            &mut [],
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    pub fn truncate_at(
        &self,
        base: StatAtBase<T::Handle>,
        path: &str,
        length: u64,
    ) -> Result<(), ClientError<T::Error>> {
        let (base, directory) = match base {
            StatAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
            StatAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
            StatAtBase::Directory(handle) => (protocol::OpenBase::AttachedDirectory, Some(handle)),
        };
        let mut payload = [0u8; protocol::TRUNCATE_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
        let payload_len = protocol::encode_truncate_at(
            protocol::TruncateAtRequest { base, length, path },
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
            protocol::OP_TRUNCATE_AT,
            0,
            &payload[..payload_len],
            &mut [],
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    pub fn symlink_at(
        &self,
        target: &str,
        base: StatAtBase<T::Handle>,
        link_path: &str,
    ) -> Result<(), ClientError<T::Error>> {
        let (base, directory) = match base {
            StatAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
            StatAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
            StatAtBase::Directory(handle) => (protocol::OpenBase::AttachedDirectory, Some(handle)),
        };
        let mut payload = [0u8; protocol::SYMLINK_AT_HEADER_LEN + protocol::MAX_PATH_LEN * 2];
        let payload_len = protocol::encode_symlink_at(
            protocol::SymlinkAtRequest {
                base,
                target,
                link_path,
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
            protocol::OP_SYMLINK_AT,
            0,
            &payload[..payload_len],
            &mut [],
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    /// Reads a symbolic-link target without appending a trailing NUL byte.
    pub fn readlink_at(
        &self,
        base: StatAtBase<T::Handle>,
        path: &str,
        output: &mut [u8],
    ) -> Result<usize, ClientError<T::Error>> {
        let (base, directory) = match base {
            StatAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
            StatAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
            StatAtBase::Directory(handle) => (protocol::OpenBase::AttachedDirectory, Some(handle)),
        };
        let mut payload = [0u8; protocol::STAT_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
        let payload_len = protocol::encode_stat_at(
            protocol::StatAtRequest {
                base,
                flags: 0,
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
        let mut target = [0u8; protocol::MAX_PATH_LEN];
        let length = self.request_with_handles(
            protocol::OP_READLINK_AT,
            0,
            &payload[..payload_len],
            &mut target,
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        let copied = core::cmp::min(length, output.len());
        output[..copied].copy_from_slice(&target[..copied]);
        Ok(copied)
    }

    pub fn chmod_at(
        &self,
        base: StatAtBase<T::Handle>,
        path: &str,
        mode: u32,
    ) -> Result<(), ClientError<T::Error>> {
        let (base, directory) = match base {
            StatAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
            StatAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
            StatAtBase::Directory(handle) => (protocol::OpenBase::AttachedDirectory, Some(handle)),
        };
        let mut payload = [0u8; protocol::OPEN_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
        let payload_len = protocol::encode_open_at(
            protocol::OpenAtRequest {
                base,
                options: 0,
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
            protocol::OP_CHMOD_AT,
            0,
            &payload[..payload_len],
            &mut [],
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    pub fn chown_at(
        &self,
        base: StatAtBase<T::Handle>,
        path: &str,
        uid: u32,
        gid: u32,
        flags: u32,
    ) -> Result<(), ClientError<T::Error>> {
        let (base, directory) = match base {
            StatAtBase::ProcessRoot => (protocol::OpenBase::ProcessRoot, None),
            StatAtBase::ProcessCwd => (protocol::OpenBase::ProcessCwd, None),
            StatAtBase::Directory(handle) => (protocol::OpenBase::AttachedDirectory, Some(handle)),
        };
        let mut payload = [0u8; protocol::CHOWN_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
        let payload_len = protocol::encode_chown_at(
            protocol::ChownAtRequest {
                base,
                flags,
                uid,
                gid,
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
            protocol::OP_CHOWN_AT,
            0,
            &payload[..payload_len],
            &mut [],
            &mut handles,
        )?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
    }

    pub fn fchmod(
        &self,
        file: ObjectHandleAttachment<T::Handle>,
        mode: u32,
    ) -> Result<(), ClientError<T::Error>> {
        self.file_operation(protocol::OP_FCHMOD, &mode.to_le_bytes(), file)
    }

    pub fn fchown(
        &self,
        file: ObjectHandleAttachment<T::Handle>,
        uid: u32,
        gid: u32,
    ) -> Result<(), ClientError<T::Error>> {
        let mut payload = [0; protocol::FILE_OWNER_PAYLOAD_LEN];
        protocol::encode_file_owner(uid, gid, &mut payload).map_err(ClientError::Protocol)?;
        self.file_operation(protocol::OP_FCHOWN, &payload, file)
    }

    fn file_operation(
        &self,
        opcode: u16,
        payload: &[u8],
        file: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        handles
            .push(file)
            .map_err(|_| ClientError::RequestTooLarge)?;
        self.request_with_handles(opcode, 0, payload, &mut [], &mut handles)?;
        if !handles.is_empty() {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(())
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
            .call_with_handles(&request_bytes[..request_len], &mut response_bytes, handles)
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

/// Minimal endpoint transport for runtimes which cannot depend on the full
/// user platform crate (notably the newlib compatibility runtime).
#[cfg(feature = "syscall-endpoint")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyscallEndpointTransport {
    endpoint: u32,
}

#[cfg(feature = "syscall-endpoint")]
impl SyscallEndpointTransport {
    pub const fn new(endpoint: u32) -> Self {
        Self { endpoint }
    }

    pub fn from_launch_context() -> Result<Self, mochi_user_syscall::SysError> {
        let raw = mochi_user_syscall::call1(
            mochi_user_syscall::SyscallNumber::LaunchHandleGet,
            protocol::CONTROL_HANDLE_KEY,
        )?;
        let endpoint = u32::try_from(raw).map_err(|_| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EOVERFLOW as i64)
        })?;
        Ok(Self::new(endpoint))
    }

    pub const fn endpoint(self) -> u32 {
        self.endpoint
    }
}

#[cfg(feature = "syscall-endpoint")]
impl Client<SyscallEndpointTransport> {
    /// Connects using only the raw mnu syscall crate, then creates the
    /// authenticated POSIX session for this process.
    pub fn from_syscall_launch_context() -> Result<Self, ClientError<mochi_user_syscall::SysError>>
    {
        let transport =
            SyscallEndpointTransport::from_launch_context().map_err(ClientError::Transport)?;
        let client = Self::new(transport);
        client.register_session()?;
        Ok(client)
    }
}

#[cfg(feature = "syscall-endpoint")]
impl Transport for SyscallEndpointTransport {
    type Error = mochi_user_syscall::SysError;

    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, Self::Error> {
        let received = mochi_user_syscall::call5(
            mochi_user_syscall::SyscallNumber::IpcCall,
            self.endpoint as u64,
            request.as_ptr() as u64,
            request.len() as u64,
            response.as_mut_ptr() as u64,
            response.len() as u64,
        )?;
        let length = (received & 0xffff_ffff) as usize;
        if length > response.len() {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EOVERFLOW as i64,
            ));
        }
        Ok(length)
    }
}

#[cfg(feature = "syscall-endpoint")]
impl ObjectTransport for SyscallEndpointTransport {
    type Handle = u32;

    fn call_with_handles(
        &self,
        request: &[u8],
        response: &mut [u8],
        handles: &mut ObjectHandles<Self::Handle>,
    ) -> Result<usize, Self::Error> {
        let mut native = mochi_user_syscall::IpcObjectHandles::default();
        native.count = handles.len() as u32;
        for (index, attachment) in handles.iter().enumerate() {
            native.handles[index].handle = attachment.handle;
            native.handles[index].rights = attachment.rights;
        }
        let received = mochi_user_syscall::call6(
            mochi_user_syscall::SyscallNumber::IpcCallObjectHandles,
            self.endpoint as u64,
            request.as_ptr() as u64,
            request.len() as u64,
            response.as_mut_ptr() as u64,
            response.len() as u64,
            (&mut native as *mut mochi_user_syscall::IpcObjectHandles) as u64,
        )?;
        let count = usize::try_from(native.count).map_err(|_| {
            mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EOVERFLOW as i64)
        })?;
        if count > MAX_OBJECT_HANDLES || native.reserved != 0 {
            close_syscall_attachments(&native, count);
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
        if native
            .handles
            .iter()
            .take(count)
            .any(|attachment| attachment.handle == 0 || attachment.reserved != 0)
        {
            close_syscall_attachments(&native, count);
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EINVAL as i64,
            ));
        }
        handles.clear();
        for attachment in native.handles.iter().take(count) {
            handles
                .push(ObjectHandleAttachment {
                    handle: attachment.handle,
                    rights: attachment.rights,
                })
                .map_err(|_| {
                    mochi_user_syscall::SysError::from_raw(mochi_user_syscall::EOVERFLOW as i64)
                })?;
        }
        let length = (received & 0xffff_ffff) as usize;
        if length > response.len() {
            return Err(mochi_user_syscall::SysError::from_raw(
                mochi_user_syscall::EOVERFLOW as i64,
            ));
        }
        Ok(length)
    }
}

#[cfg(feature = "syscall-endpoint")]
fn close_syscall_attachments(native: &mochi_user_syscall::IpcObjectHandles, count: usize) {
    for attachment in native.handles.iter().take(count.min(MAX_OBJECT_HANDLES)) {
        if attachment.handle != 0 {
            let _ = mochi_user_syscall::call1(
                mochi_user_syscall::SyscallNumber::HandleClose,
                attachment.handle as u64,
            );
        }
    }
}

/// Native fast-path backend for descriptors that already contain an object
/// handle. No request is sent to `posix.service` for these operations.
#[cfg(all(feature = "endpoint", feature = "fd-table"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeFileOps;

#[cfg(all(feature = "endpoint", feature = "fd-table"))]
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

#[cfg(all(feature = "endpoint", feature = "fd-table"))]
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
