//! User-space meaning for generic initial VM mappings. No kernel-side keys,
//! service identity, descriptor numbers or resource-limit policy are involved.
use super::*;
use mnu_abi::process_image::InitialMapping;

pub(super) struct Plan {
    handle: u32,
    base: u64,
}

impl Plan {
    pub(super) fn new(random: [u8; 16]) -> Result<Self, c_int> {
        let handle = posix_client()
            .map_err(map_posix_client_error)?
            .resource_policy_handle()
            .map_err(map_posix_client_error)?
            .handle;
        let plan = Self {
            handle,
            // A user-runtime placement preference, not a kernel convention.
            // The prepared target must reject collisions, never replace them.
            base: 0x0000_4000_0000_0000
                + (u64::from_le_bytes(random[..8].try_into().unwrap()) & 0xffff) * 0x40000,
        };
        if syscall_errno(syscall::raw_syscall1(
            syscall::SyscallNumber::HandleRightsGet,
            u64::from(handle),
        ))? != posix_protocol::resource_policy::READER_RIGHTS
        {
            return Err(EACCES);
        }
        if syscall_errno(syscall::raw_syscall1(
            syscall::SyscallNumber::MemoryObjectLength,
            u64::from(handle),
        ))? != PAGE_SIZE as u64
        {
            return Err(EIO);
        }
        Ok(plan)
    }

    pub(super) fn auxiliary(&self) -> [(u64, u64); 3] {
        [
            (
                mochios_posix_client::process_image::AT_RESOURCE_POLICY,
                self.base,
            ),
            (
                mochios_posix_client::process_image::AT_UPCALL_STACK,
                self.base + PAGE_SIZE as u64,
            ),
            (
                mochios_posix_client::process_image::AT_INITIAL_HEAP,
                self.base + PAGE_SIZE as u64 + SIGNAL_UPCALL_STACK_SIZE as u64,
            ),
        ]
    }

    pub(super) fn mappings(&self) -> [InitialMapping; 3] {
        [
            InitialMapping {
                address: self.base,
                length: PAGE_SIZE as u64,
                access: mnu_abi::MEMORY_ACCESS_READ,
                options: mnu_abi::MEMORY_MAP_SHARED,
                backing_handle: u64::from(self.handle),
                backing_offset: 0,
            },
            InitialMapping {
                address: self.base + PAGE_SIZE as u64 + SIGNAL_UPCALL_STACK_SIZE as u64,
                length: mochios_posix_client::process_image::INITIAL_HEAP_BYTES,
                access: NATIVE_READ_WRITE,
                options: 0,
                backing_handle: 0,
                backing_offset: 0,
            },
            InitialMapping {
                address: self.base + PAGE_SIZE as u64,
                length: SIGNAL_UPCALL_STACK_SIZE as u64,
                access: NATIVE_READ_WRITE,
                options: 0,
                backing_handle: 0,
                backing_offset: 0,
            },
        ]
    }
}

impl Drop for Plan {
    fn drop(&mut self) {
        close_object_handle(self.handle);
    }
}
