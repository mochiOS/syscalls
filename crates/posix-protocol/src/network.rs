//! Userspace boot endpoint handoff. No path, service name or PID in the wire.
pub const fn endpoint_rights() -> u64 {
    mnu_abi::HANDLE_RIGHT_SEND | mnu_abi::HANDLE_RIGHT_DUPLICATE | mnu_abi::HANDLE_RIGHT_TRANSFER
}

pub const fn client_endpoint_rights() -> u64 {
    mnu_abi::HANDLE_RIGHT_SEND | mnu_abi::HANDLE_RIGHT_TRANSFER
}
