//! Resolve through POSIX's retained root/cwd, never by lexical concatenation.
use super::*;

// Newlib's public sys/syslimits.h promises PATH_MAX bytes for a caller-owned
// realpath buffer. The wire limit is larger and must not dictate this C ABI.
pub(super) const OUTPUT_PATH_MAX: usize = 1024;

struct PendingOutput {
    allocation: *mut c_void,
    published: bool,
    completion: Option<mochios_posix_client::upcall_guard::Guard<'static>>,
}

impl Drop for PendingOutput {
    fn drop(&mut self) {
        if !self.published {
            unsafe { free(self.allocation) };
        }
    }
}

pub(super) fn resolve(path: *const c_char, output: *mut c_char) -> Result<*mut c_char, c_int> {
    let mut canonical = [0u8; posix_protocol::MAX_PATH_LEN];
    let length = path_io::at(-2, path, |base, path| {
        posix_client()
            .map_err(map_posix_client_error)?
            .canonical_path_at(base, path, &mut canonical)
            .map_err(map_posix_client_error)
    })?;
    let canonical = canonical.get(..length).ok_or(EIO)?;
    if canonical.first() != Some(&b'/') || canonical.contains(&0) {
        return Err(EIO);
    }
    let needed = length.checked_add(1).ok_or(EIO)?;
    if !output.is_null() {
        if needed > OUTPUT_PATH_MAX {
            return Err(ENAMETOOLONG);
        }
        if (output as usize).checked_add(needed).is_none() {
            return Err(EFAULT);
        }
        user_copy::write_c_string(output.cast(), canonical)?;
        return Ok(output);
    }
    // Allocate only after pathname RPC has completed and its scope retired.
    // Keep the allocation tracked until the final non-waiting C handoff.
    io_resources::with(
        || {
            let allocation = unsafe { malloc(needed) };
            if allocation.is_null() {
                return Err(ENOMEM);
            }
            Ok(PendingOutput {
                allocation,
                published: false,
                completion: None,
            })
        },
        |pending| {
            pending.completion = defer_native_delivery();
            unsafe {
                let output = pending.allocation.cast::<u8>();
                ptr::copy_nonoverlapping(canonical.as_ptr(), output, length);
                output.add(length).write(0);
            }
            pending.published = true;
            Ok(pending.allocation.cast())
        },
    )
}
