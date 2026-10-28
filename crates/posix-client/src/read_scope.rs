use super::*;
use protocol::read_scope as wire;

impl<T: ObjectTransport> Client<T> {
    /// Capture this authenticated caller's current root, cwd and credentials.
    /// The returned reference is owned by the caller and may be delegated.
    /// Its lifetime is the native object's lifetime, independent of the source
    /// process. It cannot be used as a writable file or as a control endpoint.
    pub fn create_read_scope(
        &self,
    ) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
        self.read_scope_object(
            wire::OP_CREATE,
            &[],
            ObjectHandles::new(),
            wire::TOKEN_RIGHTS,
        )
    }

    pub fn read_scope_info(
        &self,
        scope: ObjectHandleAttachment<T::Handle>,
    ) -> Result<protocol::SessionInfo, ClientError<T::Error>> {
        let mut handles = self.read_scope_attachment(scope)?;
        let mut response = [0; protocol::SESSION_INFO_LEN];
        let length =
            self.request_without_reply_handles(wire::OP_INFO, &[], &mut response, &mut handles)?;
        protocol::decode_session_info(&response[..length]).map_err(ClientError::Protocol)
    }

    /// Register a fresh broker-created image only while its requester's root,
    /// cwd, credentials and native image still match the loader's scope.
    /// EAGAIN requires a fresh capture and preparation; no child was registered.
    /// All inputs are borrowed, and identities are native Process attachments.
    pub fn register_launched_child_in_scope(
        &self,
        scope: ObjectHandleAttachment<T::Handle>,
        requester: ObjectHandleAttachment<T::Handle>,
        child: ObjectHandleAttachment<T::Handle>,
    ) -> Result<(), ClientError<T::Error>> {
        let mut handles = self.read_scope_attachment(scope)?;
        for (source, rights) in [
            (requester, mnu_abi::HANDLE_RIGHT_WAIT),
            (
                child,
                mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_SIGNAL,
            ),
        ] {
            if source.handle == T::Handle::default() || source.rights & rights != rights {
                return Err(ClientError::Remote(-13));
            }
            handles
                .push(ObjectHandleAttachment { rights, ..source })
                .map_err(|_| ClientError::RequestTooLarge)?;
        }
        self.request_without_reply_handles(wire::OP_REGISTER_CHILD, &[], &mut [], &mut handles)?;
        Ok(())
    }

    /// Open using only the captured scope, rather than the receiver's ambient
    /// root/cwd or credentials. Returned files have no WRITE/CONTROL authority.
    pub fn read_scope_open(
        &self,
        scope: ObjectHandleAttachment<T::Handle>,
        from_root: bool,
        path: impl AsRef<[u8]>,
    ) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
        let handles = self.read_scope_attachment(scope)?;
        let mut payload = [0; protocol::OPEN_AT_HEADER_LEN + protocol::MAX_PATH_LEN];
        let length = protocol::encode_open_at(
            protocol::OpenAtRequest {
                base: if from_root {
                    protocol::OpenBase::ProcessRoot
                } else {
                    protocol::OpenBase::ProcessCwd
                },
                options: protocol::OPEN_READ | protocol::OPEN_NONBLOCK,
                mode: 0,
                path: path.as_ref(),
            },
            &mut payload,
        )
        .map_err(ClientError::Protocol)?;
        self.read_scope_object(
            wire::OP_OPEN,
            &payload[..length],
            handles,
            wire::FILE_RIGHTS,
        )
    }

    fn read_scope_attachment(
        &self,
        scope: ObjectHandleAttachment<T::Handle>,
    ) -> Result<ObjectHandles<T::Handle>, ClientError<T::Error>> {
        if scope.handle == T::Handle::default() || scope.rights & wire::ATTACH_RIGHTS == 0 {
            return Err(ClientError::Remote(-13));
        }
        let mut handles = ObjectHandles::new();
        handles
            .push(ObjectHandleAttachment {
                rights: wire::ATTACH_RIGHTS,
                ..scope
            })
            .map_err(|_| ClientError::RequestTooLarge)?;
        Ok(handles)
    }

    fn read_scope_object(
        &self,
        opcode: u16,
        payload: &[u8],
        mut handles: ObjectHandles<T::Handle>,
        rights: u64,
    ) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
        let borrowed = handles.clone();
        let result = self.request_with_handles(opcode, 0, payload, &mut [], &mut handles);
        if matches!(result, Ok(0))
            && handles.len() == 1
            && let Some(object) = handles.get(0)
            && object.handle != T::Handle::default()
            && object.rights == rights
            && !borrowed.iter().any(|source| source.handle == object.handle)
        {
            handles.clear();
            return Ok(object);
        }
        self.discard_received_handles(&mut handles, &borrowed);
        result?;
        Err(ClientError::MismatchedResponse)
    }
}
