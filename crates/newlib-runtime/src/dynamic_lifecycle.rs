//! The CRT consumes its userspace startup plan only after runtime setup.
use super::*;
use mochios_posix_client::lifecycle_image::{Error, Image, State};
static BASE: AtomicUsize = AtomicUsize::new(0);
static LIFECYCLE: State = State::new();

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __mochios_lifecycle_v1() -> u64 {
    1
}

fn read(address: u64, bytes: &mut [u8]) -> Result<(), c_int> {
    let address = usize::try_from(address).map_err(|_| EFAULT)?;
    user_copy::read(address as *const u8, bytes)
}
fn error(error: Error<c_int>) -> c_int {
    match error {
        Error::Read(error) => error,
        Error::Invalid => ENOEXEC,
        Error::TooLarge => E2BIG,
    }
}
fn call(address: u64) -> Result<(), c_int> {
    let address = usize::try_from(address).map_err(|_| ENOEXEC)?;
    // SAFETY: the userspace exec producer resolved and validated these code
    // addresses against the installed scope before encoding the startup plan.
    let function: unsafe extern "C" fn() = unsafe { core::mem::transmute(address) };
    unsafe { function() };
    Ok(())
}
pub(super) fn initialize() -> Result<bool, c_int> {
    let Some(vector) = auxiliary::vector() else {
        return Ok(false);
    };
    let address =
        match vector.lookup(mochios_posix_client::process_image::AT_LIFECYCLE_IMAGE as usize) {
            Ok(address) => address,
            Err(ENOENT) => return Ok(false),
            Err(error) => return Err(error),
        };
    let image = Image::read(
        address as u64,
        mnu_abi::process_image::MAX_STACK_BYTES,
        read,
    )
    .map_err(error)?;
    BASE.store(address, Ordering::Release);
    LIFECYCLE.initialize(&image, read, call).map_err(error)?;
    Ok(true)
}
pub(super) fn finalize() -> Result<bool, c_int> {
    let address = BASE.load(Ordering::Acquire);
    if address == 0 {
        return Ok(false);
    }
    let image = Image::read(
        address as u64,
        mnu_abi::process_image::MAX_STACK_BYTES,
        read,
    )
    .map_err(error)?;
    LIFECYCLE.finalize(&image, read, call).map_err(error)?;
    Ok(true)
}
