//! Snapshot the caller's opaque spawn attribute handle before creating a child.
use super::*;

macro_rules! scalar {
    ($bytes:ident, $field:ident, $integer:ty) => {{
        let offset = core::mem::offset_of!(PosixSpawnAttr, $field);
        <$integer>::from_ne_bytes(
            $bytes[offset..offset + core::mem::size_of::<$integer>()]
                .try_into()
                .expect("spawn attribute field fits its structure"),
        )
    }};
}

pub(super) fn read_optional(attr: *const c_void) -> Result<Option<PosixSpawnAttr>, c_int> {
    if attr.is_null() {
        return Ok(None);
    }
    let _delivery = defer_native_delivery();
    let mut pointer = [0; core::mem::size_of::<usize>()];
    user_copy::read(attr.cast(), &mut pointer)?;
    let pointer = usize::from_ne_bytes(pointer);
    if pointer == 0 {
        return Err(EINVAL);
    }
    // Decode initialized bytes, not a borrowed C struct or an assumed-aligned
    // pointer. Padding is copied but never interpreted as a Rust value.
    let mut bytes = [0; core::mem::size_of::<PosixSpawnAttr>()];
    user_copy::read(pointer as *const u8, &mut bytes)?;
    let priority_offset = core::mem::offset_of!(PosixSpawnAttr, sa_schedparam)
        + core::mem::offset_of!(SchedParam, sched_priority);
    let attributes = PosixSpawnAttr {
        sa_flags: scalar!(bytes, sa_flags, i16),
        sa_pgroup: scalar!(bytes, sa_pgroup, c_int),
        sa_schedparam: SchedParam {
            sched_priority: c_int::from_ne_bytes(
                bytes[priority_offset..priority_offset + core::mem::size_of::<c_int>()]
                    .try_into()
                    .expect("scheduling priority fits spawn attributes"),
            ),
        },
        sa_schedpolicy: scalar!(bytes, sa_schedpolicy, c_int),
        sa_sigdefault: scalar!(bytes, sa_sigdefault, u64),
        sa_sigmask: scalar!(bytes, sa_sigmask, u64),
    };
    if attributes.sa_flags & mochios_posix_client::spawn::SET_PROCESS_GROUP != 0
        && attributes.sa_pgroup < 0
    {
        return Err(EINVAL);
    }
    match mochios_posix_client::spawn::classify_attribute_flags(attributes.sa_flags) {
        mochios_posix_client::spawn::AttributeFlags::Supported => Ok(Some(attributes)),
        mochios_posix_client::spawn::AttributeFlags::RequiresScheduler => Err(ENOSYS),
        mochios_posix_client::spawn::AttributeFlags::Invalid => Err(EINVAL),
    }
}
