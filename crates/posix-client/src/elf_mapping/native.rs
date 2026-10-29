//! Native VM adapter. The caller supplies its existing address-space limit and
//! callback critical-section policy; neither is looked up through ambient state.
use super::{Backend, Range};
use core::marker::PhantomData;
use mochi_user_syscall::{self as syscall, SysError, SyscallNumber, call2, call3};
pub trait Critical {
    fn run<T>(operation: impl FnOnce() -> T) -> T;
}
pub struct Memory<C> {
    byte_ceiling: u64,
    callbacks: PhantomData<fn() -> C>,
}
impl<C: Critical> Memory<C> {
    pub fn new(byte_ceiling: u64) -> Self {
        Self {
            byte_ceiling,
            callbacks: PhantomData,
        }
    }
    fn map(&self, range: Range, access: u64, options: u64) -> Result<(), SysError> {
        let address = syscall::memory::map_bounded(syscall::memory::Request {
            address: range.address,
            length: range.length,
            access,
            options,
            byte_ceiling: self.byte_ceiling,
            ..Default::default()
        })?;
        if address != range.address {
            return Err(failure());
        }
        Ok(())
    }
}
fn failure() -> SysError {
    SysError::from_raw(mnu_abi::status::Error::BackingFailure.into_raw() as i64)
}
fn zero(value: u64) -> Result<(), SysError> {
    if value == 0 { Ok(()) } else { Err(failure()) }
}
impl<C: Critical> Backend for Memory<C> {
    type Error = SysError;
    fn critical<T>(operation: impl FnOnce() -> T) -> T {
        C::run(operation)
    }
    fn reserve(&self, range: Range) -> Result<(), SysError> {
        self.map(range, 0, mnu_abi::MEMORY_MAP_EXACT)
    }
    fn populate(&self, range: Range) -> Result<(), SysError> {
        self.map(
            range,
            mnu_abi::MEMORY_ACCESS_READ | mnu_abi::MEMORY_ACCESS_WRITE,
            mnu_abi::MEMORY_MAP_EXACT | mnu_abi::MEMORY_MAP_REPLACE,
        )
    }
    fn write(&self, address: u64, bytes: &[u8]) -> Result<(), SysError> {
        for (index, chunk) in bytes.chunks(mnu_abi::memory_copy::MAX_BYTES).enumerate() {
            let destination = address
                .checked_add((index * mnu_abi::memory_copy::MAX_BYTES) as u64)
                .ok_or_else(failure)?;
            let count = call3(
                SyscallNumber::MemoryCopy,
                destination,
                chunk.as_ptr() as u64,
                chunk.len() as u64,
            )?;
            if count != chunk.len() as u64 {
                return Err(failure());
            }
        }
        Ok(())
    }
    fn protect(&self, range: Range, access: u64) -> Result<(), SysError> {
        zero(call3(
            SyscallNumber::MemoryProtect,
            range.address,
            range.length,
            access,
        )?)
    }
    fn release(&self, range: Range) -> Result<(), SysError> {
        zero(call2(
            SyscallNumber::MemoryUnmap,
            range.address,
            range.length,
        )?)
    }
}
