//! Allocation-free fork startup acknowledgement, separate from exec's EOF
//! protocol: an empty or truncated stream is never proof of child readiness.
use mochios_posix_client::newlib_errno::{EINTR, EIO};

pub fn send(status: i32, mut write: impl FnMut(&[u8]) -> Result<usize, i32>) -> Result<(), i32> {
    if status < 0 {
        return Err(EIO);
    }
    let packet = status.to_ne_bytes();
    let mut offset = 0;
    while offset < packet.len() {
        match write(&packet[offset..]) {
            Err(EINTR) => continue,
            Err(error) => return Err(error),
            Ok(0) => return Err(EIO),
            Ok(count) if count <= packet.len() - offset => offset += count,
            Ok(_) => return Err(EIO),
        }
    }
    Ok(())
}

pub fn receive(mut read: impl FnMut(&mut [u8]) -> Result<usize, i32>) -> Result<(), i32> {
    let mut packet = [0; core::mem::size_of::<i32>()];
    let mut offset = 0;
    while offset < packet.len() {
        match read(&mut packet[offset..]) {
            Err(EINTR) => continue,
            Err(error) => return Err(error),
            Ok(0) => return Err(EIO),
            Ok(count) if count <= packet.len() - offset => offset += count,
            Ok(_) => return Err(EIO),
        }
    }
    match i32::from_ne_bytes(packet) {
        0 => Ok(()),
        error if error > 0 => Err(error),
        _ => Err(EIO),
    }
}
