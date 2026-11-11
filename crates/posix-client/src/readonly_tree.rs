use super::*;
use mochios_filesystem_protocol::readonly_tree as wire;
impl<T: ObjectTransport> Client<T> {
    /// Publish an immutable copy of explicitly owned RAM as a read-only
    /// directory. This grants no ambient file access. The source is borrowed;
    /// the returned native reference is owned and must eventually be closed.
    /// Its contents use `mochios_filesystem_protocol::readonly_tree` encoding.
    pub fn create_readonly_tree(
        &self,
        source: ObjectHandleAttachment<T::Handle>,
        length: usize,
    ) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
        let rights = mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_TRANSFER;
        if source.handle == T::Handle::default()
            || source.rights & rights != rights
            || !(wire::REQUEST_LEN..=wire::MAX_BYTES).contains(&length)
        {
            return Err(ClientError::Remote(-22));
        }
        let mut request = [0; wire::REQUEST_LEN];
        request[..8].copy_from_slice(&wire::MAGIC);
        request[8..].copy_from_slice(&(length as u64).to_le_bytes());
        let mut handles = ObjectHandles::new();
        handles
            .push(ObjectHandleAttachment { rights, ..source })
            .map_err(|_| ClientError::RequestTooLarge)?;
        let borrowed = handles.clone();
        let mut response = [0; 8];
        let result = self
            .transport
            .call_with_handles(&request, &mut response, &mut handles)
            .map_err(ClientError::Transport);
        let expected = mnu_abi::HANDLE_RIGHT_READ
            | mnu_abi::HANDLE_RIGHT_SEEK
            | mnu_abi::HANDLE_RIGHT_DUPLICATE
            | mnu_abi::HANDLE_RIGHT_TRANSFER;
        let status = i64::from_le_bytes(response);
        if matches!(result, Ok(8))
            && status == 0
            && handles.len() == 1
            && let Some(object) = handles.get(0)
            && object.handle != T::Handle::default()
            && object.handle != source.handle
            && object.rights == expected
        {
            handles.clear();
            return Ok(object);
        }
        self.discard_received_handles(&mut handles, &borrowed);
        result?;
        if status < 0 && status >= i32::MIN as i64 {
            return Err(ClientError::Remote(status as i32));
        }
        Err(ClientError::MismatchedResponse)
    }
}
