//! POSIX system identity comes from its userspace namespace, not a syscall.
use super::*;
use posix_protocol::system_identity as wire;

fn with_identity(
    body: impl FnOnce(wire::Record<'_>) -> Result<c_int, c_int>,
) -> Result<c_int, c_int> {
    let mut bytes = [0; wire::MAX_RECORD];
    let size = posix_client()
        .map_err(map_posix_client_error)?
        .system_identity(&mut bytes)
        .map_err(map_posix_client_error)?;
    body(wire::decode(&bytes[..size]).map_err(|_| EIO)?)
}

#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub extern "C" fn uname(output: *mut c_void) -> c_int {
    if output.is_null() {
        set_errno(EFAULT);
        return -1;
    }
    result_with_errno(
        with_identity(|record| {
            let mut bytes = [0u8; wire::FIELD_COUNT * wire::FIELD_CAPACITY];
            for (index, field) in [
                record.system,
                record.node,
                record.release,
                record.version,
                record.machine,
            ]
            .iter()
            .enumerate()
            {
                let offset = index * wire::FIELD_CAPACITY;
                bytes[offset..offset + field.len()].copy_from_slice(field);
            }
            user_copy::write(output.cast(), &bytes)?;
            Ok(0)
        }),
        -1,
    )
}

#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub extern "C" fn gethostname(output: *mut c_char, length: usize) -> c_int {
    result_with_errno(
        with_identity(|record| {
            if length <= record.node.len() {
                return Err(ENAMETOOLONG);
            }
            user_copy::write_c_string(output.cast(), record.node)?;
            Ok(0)
        }),
        -1,
    )
}

#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub extern "C" fn sethostname(name: *const c_char, length: usize) -> c_int {
    let result = (|| {
        if length > wire::HOST_NAME_MAX {
            return Err(EINVAL);
        }
        let mut bytes = [0; wire::HOST_NAME_MAX];
        user_copy::read(name.cast(), &mut bytes[..length])?;
        posix_client()
            .map_err(map_posix_client_error)?
            .set_hostname(&bytes[..length])
            .map_err(map_posix_client_error)?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}
