//! Private PTY-provider control protocol. Authority travels only in attachments;
//! request bytes contain neither process identifiers nor provider object IDs.
pub const MAGIC: [u8; 4] = *b"PTYF";
pub const VERSION: u16 = 1;
pub const REQUEST_LEN: usize = 8;
pub const OP_CREATE: u16 = 1;
pub const CREATE_REQUEST: [u8; REQUEST_LEN] = [b'P', b'T', b'Y', b'F', 1, 0, 1, 0];

/// A successful response is an eight-byte zero signed status with exactly one
/// native factory Handle. Failure is a negative POSIX wire status, no Handle.
pub fn decode(request: &[u8]) -> Result<(), i32> {
    if request.len() != REQUEST_LEN
        || request[..4] != MAGIC
        || u16::from_le_bytes([request[4], request[5]]) != VERSION
    {
        return Err(-22);
    }
    if u16::from_le_bytes([request[6], request[7]]) != OP_CREATE {
        return Err(crate::STATUS_ENOSYS);
    }
    Ok(())
}
