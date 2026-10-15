use super::*;

impl<T: ObjectTransport> Client<T> {
    /// Owns one newly received RAM Handle on success. Validate its native
    /// object type/extent before mapping; retain only a read-only view and
    /// close the Handle afterward. Fork must request the child's own page,
    /// not interpret a copied parent mapping as the new process's policy.
    pub fn resource_policy_handle(
        &self,
    ) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
        let mut handles = ObjectHandles::new();
        let borrowed = ObjectHandles::new();
        let result =
            self.request_with_handles(protocol::OP_RESOURCE_POLICY, 0, &[], &mut [], &mut handles);
        if result.is_ok()
            && handles.len() == 1
            && let Some(page) = handles.get(0)
            && page.handle != T::Handle::default()
            && page.rights == protocol::resource_policy::READER_RIGHTS
        {
            handles.clear();
            return Ok(page);
        }
        self.discard_received_handles(&mut handles, &borrowed);
        result?;
        Err(ClientError::MismatchedResponse)
    }
}
