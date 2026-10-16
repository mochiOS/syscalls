//! C pointers stop here; resource policy and authority stay in the POSIX layer.
use super::*;

fn read(source: *const NewlibRlimit) -> Result<NewlibRlimit, c_int> {
    let mut bytes = [0; core::mem::size_of::<NewlibRlimit>()];
    user_copy::read(source.cast(), &mut bytes)?;
    let soft = core::mem::offset_of!(NewlibRlimit, rlim_cur);
    let hard = core::mem::offset_of!(NewlibRlimit, rlim_max);
    Ok(NewlibRlimit {
        rlim_cur: u64::from_ne_bytes(bytes[soft..soft + 8].try_into().expect("soft limit")),
        rlim_max: u64::from_ne_bytes(bytes[hard..hard + 8].try_into().expect("hard limit")),
    })
}

fn write(destination: *mut NewlibRlimit, value: NewlibRlimit) -> Result<(), c_int> {
    let mut bytes = [0; core::mem::size_of::<NewlibRlimit>()];
    let soft = core::mem::offset_of!(NewlibRlimit, rlim_cur);
    let hard = core::mem::offset_of!(NewlibRlimit, rlim_max);
    bytes[soft..soft + 8].copy_from_slice(&value.rlim_cur.to_ne_bytes());
    bytes[hard..hard + 8].copy_from_slice(&value.rlim_max.to_ne_bytes());
    user_copy::write(destination.cast(), &bytes)
}

pub(super) fn get(resource: c_int, output: *mut NewlibRlimit) -> Result<c_int, c_int> {
    if output.is_null() {
        return Err(EFAULT);
    }
    let value = resource_limit_impl(0, resource, None)?;
    write(output, value)?;
    Ok(0)
}

pub(super) fn set(resource: c_int, input: *const NewlibRlimit) -> Result<c_int, c_int> {
    if input.is_null() {
        return Err(EFAULT);
    }
    let value = read(input)?;
    resource_limit_impl(0, resource, Some(value))?;
    Ok(0)
}

pub(super) fn exchange(
    process_id: c_int,
    resource: c_int,
    input: *const NewlibRlimit,
    output: *mut NewlibRlimit,
) -> Result<c_int, c_int> {
    // Snapshot before IPC and before copyout, including aliased new/old limits.
    let replacement = if input.is_null() {
        None
    } else {
        Some(read(input)?)
    };
    let previous = resource_limit_impl(process_id, resource, replacement)?;
    if !output.is_null() {
        // A copyout failure does not undo an already committed limit change.
        write(output, previous)?;
    }
    Ok(0)
}
