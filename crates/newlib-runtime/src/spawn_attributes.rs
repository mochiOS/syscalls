//! Checked field access and snapshots of opaque caller-owned spawn attributes.
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

pub(super) fn handle_address(attr: *const c_void) -> Result<usize, c_int> {
    if attr.is_null() {
        return Err(EINVAL);
    }
    let mut pointer = [0; core::mem::size_of::<usize>()];
    user_copy::read(attr.cast(), &mut pointer)?;
    let pointer = usize::from_ne_bytes(pointer);
    if pointer == 0 {
        Err(EINVAL)
    } else {
        Ok(pointer)
    }
}

fn field_address(
    attr: *const *mut PosixSpawnAttr,
    offset: usize,
    size: usize,
) -> Result<usize, c_int> {
    if offset.checked_add(size).ok_or(EINVAL)? > core::mem::size_of::<PosixSpawnAttr>() {
        return Err(EINVAL);
    }
    handle_address(attr.cast())?
        .checked_add(offset)
        .ok_or(EFAULT)
}

// Copy only the selected scalar field. Reading a whole C struct would also
// read padding and unrelated, possibly uninitialized or inaccessible fields.
pub(super) fn get<const N: usize>(
    attr: *const *mut PosixSpawnAttr,
    output: *mut u8,
    offset: usize,
) -> c_int {
    if output.is_null() {
        return EINVAL;
    }
    let _delivery = defer_native_delivery();
    let result = (|| {
        let source = field_address(attr, offset, N)?;
        let mut bytes = [0; N];
        user_copy::read(source as *const u8, &mut bytes)?;
        user_copy::write(output, &bytes)
    })();
    result.err().unwrap_or(0)
}

pub(super) fn set<const N: usize>(
    attr: *const *mut PosixSpawnAttr,
    input: *const u8,
    offset: usize,
) -> c_int {
    if input.is_null() {
        return EINVAL;
    }
    let _delivery = defer_native_delivery();
    let result = (|| {
        let destination = field_address(attr, offset, N)?;
        let mut bytes = [0; N];
        // Capture before modifying the object, including when input aliases
        // its storage. A failed input copy cannot apply a partial new value.
        user_copy::read(input, &mut bytes)?;
        user_copy::write(destination as *mut u8, &bytes)
    })();
    result.err().unwrap_or(0)
}

pub(super) fn read_optional(attr: *const c_void) -> Result<Option<PosixSpawnAttr>, c_int> {
    if attr.is_null() {
        return Ok(None);
    }
    let _delivery = defer_native_delivery();
    let pointer = handle_address(attr)?;
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
