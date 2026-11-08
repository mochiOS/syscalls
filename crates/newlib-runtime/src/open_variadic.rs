//! Decode the optional mode only when the supported O_CREAT flag requires it.
//! This runs before any owned file/FD resource exists and performs no IPC.

pub(super) fn mode(flags: i32, read: impl FnOnce() -> u32) -> u32 {
    const O_CREAT: i32 = 0x0200;
    if flags & O_CREAT != 0 { read() } else { 0 }
}
