//! Read the initial userspace ELF vector independently of argv/environment.
use super::{EFAULT, ENOENT, c_int, set_errno, user_copy};
use core::ffi::c_ulong;
use core::sync::atomic::{AtomicUsize, Ordering};

static BASE: AtomicUsize = AtomicUsize::new(0);
static COUNT: AtomicUsize = AtomicUsize::new(0);

// Published once during startup, before constructors or application threads.
// fork retains the initial stack mappings at their original virtual addresses.
pub(super) fn initialize(base: usize, count: usize) {
    COUNT.store(count, Ordering::Relaxed);
    BASE.store(base, Ordering::Release);
}

#[derive(Clone, Copy)]
pub(super) struct Vector {
    pub base: usize,
    pub count: usize,
}

pub(super) fn vector() -> Option<Vector> {
    let base = BASE.load(Ordering::Acquire);
    (base != 0).then(|| Vector {
        base,
        count: COUNT.load(Ordering::Relaxed),
    })
}

pub(super) use mochios_posix_client::process_image::Identity;

impl Vector {
    fn extent(self) -> Result<usize, c_int> {
        let width = 2 * core::mem::size_of::<usize>();
        let bytes = self.count.checked_mul(width).ok_or(EFAULT)?;
        self.base.checked_add(bytes).ok_or(EFAULT)?;
        Ok(width)
    }

    // The stack encoder supplies placeholders. Resolve POSIX identity in user
    // space after image-start reconciliation, before any application code.
    // Updating the actual vector also keeps direct ELF-vector readers correct.
    pub fn install_identity(self, identity: Identity) -> Result<(), c_int> {
        let width = self.extent()?;
        for index in 0..self.count {
            let address = self.base + index * width;
            let mut bytes = [0; core::mem::size_of::<usize>()];
            user_copy::read(address as *const u8, &mut bytes)?;
            let key = usize::from_ne_bytes(bytes);
            let value = match key {
                0 => break,
                11 => identity.real_uid as usize,
                12 => identity.effective_uid as usize,
                13 => identity.real_gid as usize,
                14 => identity.effective_gid as usize,
                23 => usize::from(identity.is_secure()),
                _ => continue,
            };
            user_copy::write((address + width / 2) as *mut u8, &value.to_ne_bytes())?;
        }
        Ok(())
    }

    pub fn lookup(self, key: usize) -> Result<usize, c_int> {
        if key == 0 || self.base == 0 {
            return Err(ENOENT);
        }
        let width = self.extent()?;
        for index in 0..self.count {
            let address = self.base + index * width;
            let mut pair = [0u8; 2 * core::mem::size_of::<usize>()];
            user_copy::read(address as *const u8, &mut pair)?;
            let kind = usize::from_ne_bytes(pair[..width / 2].try_into().unwrap());
            if kind == 0 {
                break;
            }
            if kind == key {
                return Ok(usize::from_ne_bytes(pair[width / 2..].try_into().unwrap()));
            }
        }
        Err(ENOENT)
    }
}

pub(super) fn install_identity(identity: Identity) -> Result<(), c_int> {
    Vector {
        base: BASE.load(Ordering::Acquire),
        count: COUNT.load(Ordering::Relaxed),
    }
    .install_identity(identity)
}

#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub extern "C" fn getauxval(key: c_ulong) -> c_ulong {
    let base = BASE.load(Ordering::Acquire);
    let vector = Vector {
        base,
        count: COUNT.load(Ordering::Relaxed),
    };
    match vector.lookup(key as usize) {
        Ok(value) => value as c_ulong,
        Err(error) => {
            set_errno(error);
            0
        }
    }
}
