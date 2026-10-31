//! getrandom 0.2 custom backend using the same native source as POSIX getentropy.
//! The final binary registers `fill`; this module never registers global symbols.
use core::num::NonZeroU32;
use getrandom02::Error;

pub fn fill_using(
    destination: &mut [u8],
    mut read: impl FnMut(&mut [u8]) -> Result<usize, i32>,
) -> Result<(), Error> {
    for chunk in destination.chunks_mut(256) {
        super::fill_entropy(chunk.len(), |offset, remaining| {
            read(&mut chunk[offset..offset + remaining])
        })
        .map_err(|error| {
            NonZeroU32::new(error as u32)
                .filter(|value| value.get() < Error::INTERNAL_START)
                .map(Error::from)
                .unwrap_or(Error::UNEXPECTED)
        })?;
    }
    Ok(())
}

/// Supply this to getrandom 0.2's register_custom_getrandom! in a native binary.
pub fn fill(destination: &mut [u8]) -> Result<(), Error> {
    fill_using(destination, |remaining| {
        mochi_user_syscall::raw_syscall2(
            mochi_user_syscall::SyscallNumber::RandomFill,
            remaining.as_mut_ptr() as u64,
            remaining.len() as u64,
        )
        .into_result()
        .map_err(|error| crate::newlib_errno::from_status(error.raw()))
        .and_then(|count| usize::try_from(count).map_err(|_| crate::newlib_errno::EIO))
    })
}
