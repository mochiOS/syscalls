//! User-space image preparation. Source references remain borrowed; every
//! allocated byte buffer and RAM reference is owned through callback abandonment.
use super::*;
#[path = "exec_image/dependencies.rs"]
mod dependencies;

const MAX_IMAGE: usize = mnu_abi::exec::MAX_CAPTURED_IMAGE_BYTES;

#[derive(Default)]
struct Buffer {
    pointer: *mut u8,
    length: usize,
    capacity: usize,
}
impl Buffer {
    fn bytes(&self) -> &[u8] {
        if self.length == 0 {
            &[]
        } else {
            unsafe { core::slice::from_raw_parts(self.pointer, self.length) }
        }
    }
    fn slots<T>(&mut self, count: usize) -> Result<*mut T, c_int> {
        let bytes = count.checked_mul(core::mem::size_of::<T>()).ok_or(ENOMEM)?;
        self.reserve(bytes)?;
        self.length = bytes;
        Ok(self.pointer.cast())
    }
    fn reserve(&mut self, required: usize) -> Result<(), c_int> {
        if required > MAX_IMAGE {
            return Err(EFBIG);
        }
        if required <= self.capacity {
            return Ok(());
        }
        let capacity = required
            .checked_next_power_of_two()
            .unwrap_or(MAX_IMAGE)
            .min(MAX_IMAGE);
        let _delivery = defer_native_delivery();
        let pointer = unsafe { malloc(capacity) }.cast::<u8>();
        if pointer.is_null() {
            return Err(ENOMEM);
        }
        unsafe {
            ptr::write_bytes(pointer, 0, capacity);
            if self.length != 0 {
                ptr::copy_nonoverlapping(self.pointer, pointer, self.length);
            }
            free(self.pointer.cast());
        }
        self.pointer = pointer;
        self.capacity = capacity;
        Ok(())
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        let _delivery = defer_native_delivery();
        unsafe { free(self.pointer.cast()) };
    }
}
#[derive(Default)]
struct Preparation {
    source: Buffer,
    output: Buffer,
    dependencies: dependencies::Dependencies,
    handle: u32,
    executable: Option<mochios_posix_client::process_image::Executable>,
}
impl Drop for Preparation {
    fn drop(&mut self) {
        let _delivery = defer_native_delivery();
        if self.handle != 0 {
            close_object_handle(self.handle);
        }
    }
}
fn read_at(image: u32, output: &mut [u8], offset: usize) -> Result<usize, c_int> {
    let count = syscall_errno(syscall::raw_syscall4(
        syscall::SyscallNumber::HandleReadAt,
        u64::from(image),
        output.as_mut_ptr() as u64,
        output.len() as u64,
        offset as u64,
    ))?;
    usize::try_from(count)
        .ok()
        .filter(|count| *count <= output.len())
        .ok_or(EIO)
}
fn is_pie(image: u32) -> Result<bool, c_int> {
    let mut header = [0u8; 64];
    let mut read = 0;
    while read < header.len() {
        let n = read_at(image, &mut header[read..], read)?;
        if n == 0 {
            break;
        }
        read += n;
    }
    Ok(read == 64
        && header[..7] == [0x7f, b'E', b'L', b'F', 2, 1, 1]
        && header[16..18] == 3u16.to_le_bytes())
}
impl Preparation {
    fn build(
        &mut self,
        image: u32,
        inputs: &exec_inputs::Inputs,
        identity: mochios_posix_client::process_image::Identity,
    ) -> Result<(), c_int> {
        let mut chunk = [0u8; mnu_abi::provider::MAX_DATA_LEN];
        loop {
            let n = read_at(image, &mut chunk, self.source.length)?;
            if n == 0 {
                break;
            }
            let length = self.source.length.checked_add(n).ok_or(EFBIG)?;
            self.source.reserve(length)?;
            unsafe {
                ptr::copy_nonoverlapping(
                    chunk.as_ptr(),
                    self.source.pointer.add(self.source.length),
                    n,
                )
            };
            self.source.length = length;
        }
        let candidate = mochios_posix_client::pie::Pie::parse_object(self.source.bytes())
            .map_err(|_| ENOEXEC)?;
        let mut dependent = false;
        candidate
            .dependencies(|_| {
                dependent = true;
                Ok(())
            })
            .map_err(|_| ENOEXEC)?;
        let length = if dependent {
            self.executable = Some(self.dependencies.build(
                self.source.bytes(),
                &mut self.output,
                inputs,
                identity,
            )?);
            self.output.length
        } else {
            let pie =
                mochios_posix_client::pie::Pie::parse(self.source.bytes()).map_err(|_| ENOEXEC)?;
            let length = pie.output_length().map_err(|_| ENOEXEC)?;
            self.output.reserve(length)?;
            self.output.length = length;
            let mut entropy = [0u8; 8];
            if syscall_errno(syscall::raw_syscall2(
                syscall::SyscallNumber::RandomFill,
                entropy.as_mut_ptr() as u64,
                entropy.len() as u64,
            ))? != entropy.len() as u64
            {
                return Err(EIO);
            }
            let alignment = pie.alignment();
            let base = 0x2000_0000u64
                .checked_add(alignment - 1)
                .map(|base| base & !(alignment - 1))
                .ok_or(ENOEXEC)?;
            let slots = (64 * 1024 * 1024 / alignment).max(1);
            let bias = base
                .checked_add((u64::from_le_bytes(entropy) % slots) * alignment)
                .ok_or(ENOEXEC)?;
            self.executable = Some(pie.executable(bias).map_err(|_| ENOEXEC)?);
            let output = unsafe { core::slice::from_raw_parts_mut(self.output.pointer, length) };
            if pie.write(bias, output).map_err(|_| ENOEXEC)? != length {
                return Err(EIO);
            }
            length
        };
        {
            let _delivery = defer_native_delivery();
            let raw = syscall_errno(syscall::raw_syscall2(
                syscall::SyscallNumber::MemoryObjectCreate,
                length as u64,
                mnu_abi::MEMORY_OBJECT_RESIZABLE,
            ))?;
            self.handle = u32::try_from(raw).ok().filter(|h| *h != 0).ok_or(EIO)?;
        }
        let mut offset = 0;
        while offset < length {
            let bytes = &self.output.bytes()[offset..length.min(offset + chunk.len())];
            let n = syscall_errno(syscall::raw_syscall4(
                syscall::SyscallNumber::HandleWriteAt,
                u64::from(self.handle),
                bytes.as_ptr() as u64,
                bytes.len() as u64,
                offset as u64,
            ))?;
            let n = usize::try_from(n)
                .ok()
                .filter(|n| *n > 0 && *n <= bytes.len())
                .ok_or(EIO)?;
            offset += n;
        }
        // Keep no writable/resize alias while requesting execution authority.
        let _delivery = defer_native_delivery();
        let raw = syscall_errno(syscall::raw_syscall2(
            syscall::SyscallNumber::HandleDuplicate,
            u64::from(self.handle),
            posix_protocol::CHECK_EXECUTABLE_RIGHTS,
        ))?;
        let read = u32::try_from(raw).ok().filter(|h| *h != 0).ok_or(EIO)?;
        close_object_handle(self.handle);
        self.handle = read;
        Ok(())
    }
}

pub(super) fn with_image(
    image: u32,
    inputs: &exec_inputs::Inputs,
    identity: mochios_posix_client::process_image::Identity,
    operation: impl FnOnce(
        u32,
        Option<mochios_posix_client::process_image::Executable>,
    ) -> Result<(), c_int>,
) -> Result<(), c_int> {
    if !is_pie(image)? {
        return operation(image, None);
    }
    io_resources::with(
        || Ok(Preparation::default()),
        |preparation| {
            preparation.build(image, inputs, identity)?;
            operation(preparation.handle, preparation.executable)
        },
    )
}
