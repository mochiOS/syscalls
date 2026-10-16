//! Faultable application pointers never become Rust references. MemoryCopy
//! checks the current mapping even inside an already active native upcall.
use super::*;

fn transfer(destination: usize, source: usize, length: usize) -> Result<(), c_int> {
    if length == 0 {
        return Ok(());
    }
    destination.checked_add(length).ok_or(EFAULT)?;
    source.checked_add(length).ok_or(EFAULT)?;
    let copied = syscall_errno(syscall::raw_syscall3(
        syscall::SyscallNumber::MemoryCopy,
        destination as u64,
        source as u64,
        length as u64,
    ))?;
    if copied != length as u64 {
        return Err(EIO);
    }
    Ok(())
}

pub(super) fn write(destination: *mut u8, bytes: &[u8]) -> Result<(), c_int> {
    (destination as usize)
        .checked_add(bytes.len())
        .ok_or(EFAULT)?;
    for (index, chunk) in bytes.chunks(mnu_abi::memory_copy::MAX_BYTES).enumerate() {
        transfer(
            destination as usize + index * mnu_abi::memory_copy::MAX_BYTES,
            chunk.as_ptr() as usize,
            chunk.len(),
        )?;
    }
    Ok(())
}

pub(super) fn write_c_string(destination: *mut u8, bytes: &[u8]) -> Result<(), c_int> {
    let terminator = (destination as usize)
        .checked_add(bytes.len())
        .ok_or(EFAULT)?;
    terminator.checked_add(1).ok_or(EFAULT)?;
    write(destination, bytes)?;
    write(terminator as *mut u8, &[0])
}

pub(super) fn capture(
    path: *const c_char,
    output: &mut [u8; posix_protocol::MAX_PATH_LEN],
) -> Result<usize, c_int> {
    if path.is_null() {
        return Err(EFAULT);
    }
    let mut length = 0;
    let mut scratch = [0u8; 256];
    loop {
        let address = (path as usize).checked_add(length).ok_or(EFAULT)?;
        let count = scratch
            .len()
            .min(PAGE_SIZE - address % PAGE_SIZE)
            .min(output.len() + 1 - length);
        // Never speculatively read into the next virtual page past a valid
        // NUL. An unusual sub-page backing failure may still leave a valid
        // terminated prefix; retry that window bytewise, not by raw loads.
        let bytewise = match transfer(scratch.as_mut_ptr() as usize, address, count) {
            Ok(()) => false,
            Err(EFAULT) if count > 1 => true,
            Err(error) => return Err(error),
        };
        for index in 0..count {
            if bytewise {
                transfer(scratch.as_mut_ptr() as usize + index, address + index, 1)?;
            }
            let byte = scratch[index];
            if byte == 0 {
                return if length == 0 { Err(ENOENT) } else { Ok(length) };
            }
            if length == output.len() {
                return Err(ENAMETOOLONG);
            }
            output[length] = byte;
            length += 1;
        }
    }
}
