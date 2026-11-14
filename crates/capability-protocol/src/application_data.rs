//! Default private storage, selected exclusively from authenticated caller
//! identity and POSIX account incarnation. Requests contain no path or UID.
pub const OPCODE: u32 = u32::from_le_bytes(*b"ADIR");
pub const REQUEST: [u8; 8] = [b'A', b'D', b'I', b'R', 1, 0, 0, 0];
