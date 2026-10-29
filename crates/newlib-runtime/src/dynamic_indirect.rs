//! Initial-image resolvers run after TLS, before constructors or main.
use super::*;
use mochios_posix_client::indirect_image::{self as policy, Captured, Error, Fixup, Region, State};
static RESOLVERS: State = State::new();

/// Startup contract only. The producer separately authenticates every input
/// and obtains execution authority before the kernel installs the image.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn __mochios_indirect_v1() -> u64 {
    1
}

fn error(error: Error<c_int>) -> c_int {
    match error {
        Error::Read(error) | Error::Write(error) | Error::Resolve(error) => error,
        Error::TooLarge | Error::BufferTooSmall => E2BIG,
        Error::Invalid | Error::Reentrant | Error::Failed => ENOEXEC,
    }
}

pub(super) fn initialize() -> Result<bool, c_int> {
    let Some(vector) = auxiliary::vector() else {
        return Ok(false);
    };
    let address =
        match vector.lookup(mochios_posix_client::process_image::AT_INDIRECT_IMAGE as usize) {
            Ok(address) => address,
            Err(ENOENT) => return Ok(false),
            Err(error) => return Err(error),
        };
    const MAXIMUM: usize = mnu_abi::process_image::MAX_STACK_BYTES;
    // The bounded startup payload fits in the existing native entry stack.
    // Both workspaces are private; no allocation/Handle survives a resolver
    // which exits or abandons this frame with a C nonlocal jump.
    let mut regions = [Region::EMPTY; (MAXIMUM - policy::HEADER_BYTES) / policy::REGION_BYTES];
    let mut fixups = [Fixup::EMPTY; (MAXIMUM - policy::HEADER_BYTES) / policy::FIXUP_BYTES];
    let image = Captured::capture(
        address as u64,
        MAXIMUM,
        &mut regions,
        &mut fixups,
        |address, bytes| user_copy::read(address as *const u8, bytes),
    )
    .map_err(error)?;
    RESOLVERS
        .apply(
            &image,
            |address| -> Result<u64, c_int> {
                // SAFETY: capture checked every resolver against the authorized
                // installed executable LOADs before the first function is invoked.
                let resolver: unsafe extern "C" fn() -> u64 =
                    unsafe { core::mem::transmute(address as usize) };
                Ok(unsafe { resolver() })
            },
            |address, bytes| user_copy::write(address as *mut u8, bytes),
        )
        .map_err(error)?;
    Ok(true)
}
