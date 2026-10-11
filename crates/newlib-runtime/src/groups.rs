// newlib's generic x86_64-elf sys/_types.h defines __gid_t as unsigned short.
// The POSIX wire format remains u32; narrow only at the public libc boundary.
pub type Gid = u16;

pub fn store(source: &[u32], destination: &mut [Gid]) -> Result<(), ()> {
    if destination.len() < source.len() || source.iter().any(|&gid| Gid::try_from(gid).is_err()) {
        return Err(());
    }
    // Validate the whole response before modifying the caller's array.
    for (output, &gid) in destination.iter_mut().zip(source) {
        *output = gid as Gid;
    }
    Ok(())
}

pub fn widen(source: &[Gid], destination: &mut [u32]) {
    assert!(destination.len() >= source.len());
    for (output, &gid) in destination.iter_mut().zip(source) {
        *output = u32::from(gid);
    }
}
