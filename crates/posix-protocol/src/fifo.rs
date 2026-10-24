//! Userspace FIFO open continuation. A pending reply owns an already registered
//! data description plus one notification; it is not a pathname replay ticket.
use crate::{OPEN_READ, OPEN_WRITE};
pub const COMMON_DATA_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_CONTROL
    | mnu_abi::HANDLE_RIGHT_DUPLICATE
    | mnu_abi::HANDLE_RIGHT_TRANSFER
    | mnu_abi::HANDLE_RIGHT_WAIT;
pub const NOTIFICATION_RIGHTS: u64 =
    mnu_abi::HANDLE_RIGHT_WAIT | mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER;
/// Only OPEN_AT with queued admission may opt in to the two-Handle reply.
pub const OPEN_CONTINUATION: u32 = 1 << 29;
/// OP_STATUS success, empty body, exactly [data, notification] attachments.
/// Await the one-shot notification outside service/runtime locks, then use
/// the same data Handle. Closing both references cancels the pending open.
pub const OPEN_PENDING_REPLY: u32 = 1;
pub fn data_rights(options: u32) -> Option<u64> {
    match options & (OPEN_READ | OPEN_WRITE) {
        OPEN_READ => Some(COMMON_DATA_RIGHTS | mnu_abi::HANDLE_RIGHT_READ),
        OPEN_WRITE => Some(COMMON_DATA_RIGHTS | mnu_abi::HANDLE_RIGHT_WRITE),
        _ => None,
    }
}
