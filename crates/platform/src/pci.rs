//! PCI configuration mediated by the userspace resource authority. Drivers
//! never receive the shared configuration address/data ports.
use crate::{
    ipc, process,
    syscall::{EINVAL, EIO, SysError},
};

pub const MAGIC: u32 = u32::from_le_bytes(*b"PCI1");
pub const READ: u32 = 0;
pub const WRITE: u32 = 1;
pub const BAR_MASK: u32 = 2;

fn call(operation: u32, address: u32, offset: u16, value: u32) -> Result<u32, SysError> {
    if address & !0x00ff_ff00 != 0 || offset >= 256 || offset & 3 != 0 {
        return Err(SysError::from_raw(EINVAL as i64));
    }
    let endpoint = process::find_by_name("capability.service")?;
    let identity = process::thread_security_context(endpoint)?;
    if identity.provenance != 1
        || identity.subject_key_id != [0; 32]
        || identity.package_id.get(..identity.package_id_len as usize)
            != Some(b"org.mochios.capability")
        || identity
            .developer_id
            .get(..identity.developer_id_len as usize)
            != Some(b"org.mochios.system")
    {
        return Err(SysError::from_raw(crate::syscall::EACCES as i64));
    }
    let mut request = [0; 20];
    for (slot, word) in
        request
            .chunks_exact_mut(4)
            .zip([MAGIC, operation, address, u32::from(offset), value])
    {
        slot.copy_from_slice(&word.to_le_bytes());
    }
    let mut reply = [0; 16];
    let length = ipc::call(endpoint, &request, &mut reply)? as u32 as usize;
    if length != reply.len() {
        return Err(SysError::from_raw(EIO as i64));
    }
    let status = i64::from_le_bytes(reply[..8].try_into().unwrap());
    if status != 0 {
        return Err(SysError::from_raw(status));
    }
    Ok(u64::from_le_bytes(reply[8..].try_into().unwrap()) as u32)
}

/// BAR sizing is emulated locally from owner-supplied masks. An all-ones
/// driver write must never reprogram a live hardware BAR, even transiently.
#[derive(Default)]
pub struct Config {
    probing: [Option<u32>; 6],
    available: Option<bool>,
}
impl Config {
    pub fn read(&mut self, address: u32, offset: u16) -> Result<u32, SysError> {
        if offset >= 256 || offset & 3 != 0 {
            return Err(SysError::from_raw(EINVAL as i64));
        }
        if self.available.is_none() {
            self.available = Some(call(3, 0, 0, 0)? != 0);
        }
        if self.available == Some(false) {
            return Ok(u32::MAX);
        }
        let operation = if (0x10..0x28).contains(&offset)
            && self.probing[usize::from((offset - 0x10) / 4)] == Some(address)
        {
            BAR_MASK
        } else {
            READ
        };
        call(operation, address, offset, 0)
    }
    pub fn write(&mut self, address: u32, offset: u16, value: u32) -> Result<(), SysError> {
        if (0x10..0x28).contains(&offset) && offset & 3 == 0 {
            let index = usize::from((offset - 0x10) / 4);
            if value == u32::MAX {
                // Authenticate the device even for the emulated write.
                call(BAR_MASK, address, offset, 0)?;
                self.probing[index] = Some(address);
                return Ok(());
            }
            call(WRITE, address, offset, value)?;
            self.probing[index] = None;
            return Ok(());
        }
        call(WRITE, address, offset, value).map(|_| ())
    }
}
