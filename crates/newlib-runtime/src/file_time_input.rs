//! Snapshot the entire C array before obtaining resources or issuing a mutation.
//! Faultable caller memory is copied, never dereferenced as a Rust timespec.
use super::*;
use posix_protocol::file_time::{Change, Update};

// newlib/mochiOS C ABI, not Linux's positive sentinel values or IPC tags.
pub(super) const UTIME_NOW: CLong = -2;
pub(super) const UTIME_OMIT: CLong = -1;

pub(super) fn read(times: *const Timespec) -> Result<Update, c_int> {
    if times.is_null() {
        return Ok(Update::now());
    }
    let mut bytes = [0; 2 * core::mem::size_of::<Timespec>()];
    user_copy::read(times.cast(), &mut bytes)?;
    fn field(bytes: &[u8]) -> Result<Change, c_int> {
        let seconds = core::mem::offset_of!(Timespec, tv_sec);
        let nanos = core::mem::offset_of!(Timespec, tv_nsec);
        let nanoseconds = CLong::from_ne_bytes(bytes[nanos..nanos + 8].try_into().unwrap());
        match nanoseconds {
            UTIME_NOW => Ok(Change::Now),
            UTIME_OMIT => Ok(Change::Omit),
            0..1_000_000_000 => Ok(Change::Set {
                seconds: CLong::from_ne_bytes(bytes[seconds..seconds + 8].try_into().unwrap()),
                nanoseconds: nanoseconds as u32,
            }),
            _ => Err(EINVAL),
        }
    }
    let (access, modification) = bytes.split_at(core::mem::size_of::<Timespec>());
    Ok(Update {
        access: field(access)?,
        modification: field(modification)?,
    })
}
