//! Public named semaphore ABI. Only discovery/unlink use userspace IPC.

use super::*;
use mochios_posix_client::named_semaphore::{Error, MappingOps};
use mochios_posix_client::semaphore::Semaphore;
use mochios_posix_protocol::named_semaphore as wire;

const PAGE_SIZE: u64 = 4096;
// newlib fcntl ABI; these flags are translated before entering the wire API.
const O_CREAT: c_int = 0x0200;
const O_EXCL: c_int = 0x0800;
const RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_READ
    | mnu_abi::HANDLE_RIGHT_WRITE
    | mnu_abi::HANDLE_RIGHT_MAP
    | mnu_abi::HANDLE_RIGHT_DUPLICATE
    | mnu_abi::HANDLE_RIGHT_TRANSFER;
struct NativeMappings(Option<address_space::Limit>);

impl NativeMappings {
    // Cleanup never maps. Do not accidentally allow a map without policy.
    fn cleanup() -> Self {
        Self(None)
    }
}

impl MappingOps<u32> for NativeMappings {
    type Error = c_int;
    fn same_object(&mut self, left: u32, right: u32) -> Result<bool, c_int> {
        match syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::HandleSameObject,
            left as u64,
            right as u64,
        ))? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(EIO),
        }
    }
    fn map(&mut self, handle: u32) -> Result<u64, c_int> {
        if syscall_errno(syscall::raw_syscall1(
            syscall::SyscallNumber::MemoryObjectLength,
            handle as u64,
        ))? != PAGE_SIZE
        {
            return Err(EIO);
        }
        let address = self.0.ok_or(EINVAL)?.map(
            0,
            PAGE_SIZE,
            mnu_abi::MEMORY_ACCESS_READ | mnu_abi::MEMORY_ACCESS_WRITE,
            mnu_abi::MEMORY_MAP_SHARED,
            handle as u64,
            0,
        )?;
        // The native MemoryObject mapping has readable/writable page backing.
        // Reject uninitialized/corrupt service state before returning a pointer.
        if address == 0 || unsafe { &*(address as *const Semaphore) }.value().is_err() {
            let _ = syscall::raw_syscall2(syscall::SyscallNumber::MemoryUnmap, address, PAGE_SIZE);
            return Err(EIO);
        }
        Ok(address)
    }
    fn unmap(&mut self, address: u64) -> Result<(), c_int> {
        syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::MemoryUnmap,
            address,
            PAGE_SIZE,
        ))
        .map(|_| ())
    }
    fn close_handle(&mut self, handle: u32) {
        let _ = syscall::raw_syscall1(syscall::SyscallNumber::HandleClose, handle as u64);
    }
}

fn error(error: Error<c_int>) -> c_int {
    match error {
        Error::Invalid => EINVAL,
        Error::Full => EMFILE,
        Error::Overflow => EOVERFLOW,
        Error::Backend(error) => error,
    }
}

pub(super) unsafe fn name<'a>(pointer: *const c_char) -> Result<&'a [u8], c_int> {
    if pointer.is_null() {
        return Err(EINVAL);
    }
    // Bounded C name scan: do not read arbitrary-length input before rejecting.
    let mut length = 0;
    while length <= wire::MAX_NAME_BYTES + 1 {
        if unsafe { pointer.add(length).read() } == 0 {
            let bytes = unsafe { core::slice::from_raw_parts(pointer.cast::<u8>(), length) };
            if bytes.first() != Some(&b'/') || length < 2 || bytes[1..].contains(&b'/') {
                return Err(EINVAL);
            }
            return Ok(bytes);
        }
        length += 1;
    }
    Err(ENAMETOOLONG)
}

fn request(opcode: u16, payload: &[u8], opened: bool) -> Result<Option<u32>, c_int> {
    let client = posix_client().map_err(map_posix_client_error)?;
    let mut handles = mochios_posix_client::ObjectHandles::new();
    let outcome = client
        .request_with_handles(opcode, 0, payload, &mut [], &mut handles)
        .map_err(map_posix_client_error);
    if outcome.is_ok() && handles.len() == usize::from(opened) {
        if !opened {
            return Ok(None);
        }
        let attachment = handles.get(0).ok_or(EIO)?;
        if attachment.rights == RIGHTS {
            return Ok(Some(attachment.handle));
        }
    }
    for attachment in handles.iter() {
        NativeMappings::cleanup().close_handle(attachment.handle);
    }
    Err(outcome.err().unwrap_or(EIO))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __mochios_sem_open(
    pointer: *const c_char,
    options: c_int,
    mode: u32,
    value: u32,
) -> *mut Semaphore {
    let outcome = (|| {
        let name = unsafe { name(pointer) }?;
        if options & !(O_CREAT | O_EXCL) != 0 || (options & O_EXCL != 0 && options & O_CREAT == 0) {
            return Err(EINVAL);
        }
        let mut payload = [0; wire::OPEN_HEADER_LEN + wire::MAX_NAME_BYTES + 1];
        let length = wire::encode_open(
            wire::Open {
                options: if options & O_CREAT != 0 {
                    wire::CREATE
                        | if options & O_EXCL != 0 {
                            wire::EXCLUSIVE
                        } else {
                            0
                        }
                } else {
                    0
                },
                mode: if options & O_CREAT != 0 { mode } else { 0 },
                value: if options & O_CREAT != 0 { value } else { 0 },
                name,
            },
            &mut payload,
        )
        .map_err(|_| EINVAL)?;
        let mut mappings = NativeMappings(Some(address_space::current()?));
        let handle =
            request(posix_protocol::OP_SEMAPHORE_OPEN, &payload[..length], true)?.ok_or(EIO)?;
        // STATE also stabilizes this table during fork; no separate lock is
        // copied in an in-progress state. Native fork preserves Handle numbers.
        state()
            .named_semaphores
            .adopt(handle, &mut mappings)
            .map_err(error)
    })();
    match outcome {
        Ok(address) => address as *mut Semaphore,
        Err(error) => {
            set_errno(error);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_close(pointer: *mut Semaphore) -> c_int {
    let outcome = state()
        .named_semaphores
        .close(pointer as u64, &mut NativeMappings::cleanup())
        .map_err(error);
    match outcome {
        Ok(()) => 0,
        Err(error) => {
            set_errno(error);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sem_unlink(pointer: *const c_char) -> c_int {
    let outcome = (|| {
        let name = unsafe { name(pointer) }?;
        let mut payload = [0; wire::NAME_HEADER_LEN + wire::MAX_NAME_BYTES + 1];
        let length = wire::encode_name(name, &mut payload).map_err(|_| EINVAL)?;
        request(
            posix_protocol::OP_SEMAPHORE_UNLINK,
            &payload[..length],
            false,
        )
        .map(|_| ())
    })();
    match outcome {
        Ok(()) => 0,
        Err(error) => {
            set_errno(error);
            -1
        }
    }
}
