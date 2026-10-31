use super::*;
use protocol::process_domain as wire;
impl<T: ObjectTransport> Client<T> {
    /// Capture trees rooted at this caller or images it actually launched.
    /// Fork/launch descendants inherit membership even after POSIX reparenting.
    /// The returned native object is owned. Source references remain borrowed.
    pub fn create_process_domain(
        &self,
        roots: &[ObjectHandleAttachment<T::Handle>],
    ) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
        if roots.len() > wire::MAX_ROOTS {
            return Err(ClientError::Remote(-22));
        }
        let mut handles = ObjectHandles::new();
        for source in roots {
            if source.handle == T::Handle::default()
                || source.rights & wire::PROCESS_RIGHTS != wire::PROCESS_RIGHTS
            {
                return Err(ClientError::Remote(-13));
            }
            handles
                .push(ObjectHandleAttachment {
                    rights: wire::PROCESS_RIGHTS,
                    ..*source
                })
                .map_err(|_| ClientError::RequestTooLarge)?;
        }
        let borrowed = handles.clone();
        let result = self.request_with_handles(wire::OP_CREATE, 0, &[], &mut [], &mut handles);
        if matches!(result, Ok(0))
            && handles.len() == 1
            && let Some(object) = handles.get(0)
            && object.handle != T::Handle::default()
            && object.rights == wire::TOKEN_RIGHTS
            && !borrowed.iter().any(|source| source.handle == object.handle)
        {
            handles.clear();
            return Ok(object);
        }
        self.discard_received_handles(&mut handles, &borrowed);
        result?;
        Err(ClientError::MismatchedResponse)
    }

    /// Register a fresh root in an owner-created domain before native resume.
    /// This closes the gap where a child could fork and reparent before capture.
    pub fn register_spawned_child_in_domain(
        &self,
        domain: ObjectHandleAttachment<T::Handle>,
        process: ObjectHandleAttachment<T::Handle>,
        uid: u32,
        gid: u32,
        groups: &[u32],
    ) -> Result<(), ClientError<T::Error>> {
        let mut payload = [0; 8 + protocol::GROUP_LIST_MAX_LEN];
        let length = protocol::encode_spawn_credentials(uid, gid, groups, &mut payload)
            .map_err(ClientError::Protocol)?;
        let mut handles = ObjectHandles::new();
        for (source, rights) in [
            (domain, wire::ATTACH_RIGHTS),
            (process, wire::PROCESS_RIGHTS | mnu_abi::HANDLE_RIGHT_SIGNAL),
        ] {
            if source.handle == T::Handle::default() || source.rights & rights != rights {
                return Err(ClientError::Remote(-13));
            }
            handles
                .push(ObjectHandleAttachment { rights, ..source })
                .map_err(|_| ClientError::RequestTooLarge)?;
        }
        self.request_without_reply_handles(
            wire::OP_SPAWN,
            &payload[..length],
            &mut [],
            &mut handles,
        )?;
        Ok(())
    }

    /// Query only the process and domain explicitly delegated to this call.
    /// No PID or native Handle number is serialized in the request payload.
    pub fn process_domain_contains(
        &self,
        domain: ObjectHandleAttachment<T::Handle>,
        process: ObjectHandleAttachment<T::Handle>,
    ) -> Result<bool, ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        for (source, rights) in [
            (domain, wire::ATTACH_RIGHTS),
            (process, wire::PROCESS_RIGHTS),
        ] {
            if source.handle == T::Handle::default() || source.rights & rights != rights {
                return Err(ClientError::Remote(-13));
            }
            handles
                .push(ObjectHandleAttachment { rights, ..source })
                .map_err(|_| ClientError::RequestTooLarge)?;
        }
        let mut response = [0; 1];
        let length = self.request_without_reply_handles(
            wire::OP_CONTAINS,
            &[],
            &mut response,
            &mut handles,
        )?;
        wire::decode_membership(&response[..length]).map_err(ClientError::Protocol)
    }
}
