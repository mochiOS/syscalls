//! Fault-aware C resolver transactions, shared by the native ABI and tests.
use super::netdb_backend::{Backend, Io};
use super::*;
use mochios_posix_client::{
    netdb::{Error, dns},
    resolver_packet as packet,
};

pub(super) fn query<I: Io>(
    backend: Backend<I>,
    name: *const c_char,
    class: c_int,
    kind: c_int,
    answer: *mut u8,
    answer_length: c_int,
    mut dns_error: impl FnMut(Error) -> c_int,
) -> Result<c_int, c_int> {
    (|| {
        let kind = packet::query_kind(class, kind).map_err(|_| ENOTSUP)?;
        let length = usize::try_from(answer_length).map_err(|_| EINVAL)?;
        if length != 0 && answer.is_null() {
            return Err(EFAULT);
        }
        // A DNS message cannot exceed 65535 bytes. Never allocate according to
        // an unbounded caller-provided int, even if its output capacity is huge.
        let length = length.min(65535);
        io_resources::with_initialized(
            || Ok((backend, VectorBuffer::new(length)?, [0u8; 1024], 0usize)),
            |(_, _, text, used)| {
                *used = user_copy::capture_text(name, text, ENAMETOOLONG)?;
                Ok(())
            },
            |(backend, output, text, used)| {
                let mut wire = [0; 255];
                let question = dns::question(&text[..*used], &mut wire).map_err(&mut dns_error)?;
                let snapshot = backend.dns(kind, question).map_err(&mut dns_error)?;
                if snapshot.status == mochios_posix_client::resolver::NO_DATA_STATUS {
                    return Err(dns_error(Error::System(snapshot.status)));
                }
                dns::status(snapshot.status).map_err(&mut dns_error)?;
                let needed = packet::reply(&snapshot, output.bytes()).map_err(|_| EOVERFLOW)?;
                user_copy::write(answer, &output.bytes()[..needed.min(length)])?;
                Ok(needed as c_int)
            },
        )
    })()
}

/// Copy and expand one caller-owned compressed DNS name without raw-pointer
/// dereferences, even when the application supplied an inaccessible mapping.
pub(super) fn expand(
    message: *const u8,
    end: *const u8,
    compressed: *const u8,
    destination: *mut c_char,
    destination_length: c_int,
) -> Result<c_int, c_int> {
    (|| {
        let start = compressed as usize;
        let base = message as usize;
        let length = (end as usize)
            .checked_sub(base)
            .filter(|n| *n <= 65535)
            .ok_or(EINVAL)?;
        let offset = start
            .checked_sub(base)
            .filter(|n| *n < length)
            .ok_or(EINVAL)?;
        let capacity = usize::try_from(destination_length).map_err(|_| EINVAL)?;
        if capacity == 0 {
            return Err(ERANGE);
        }
        io_resources::with(
            || VectorBuffer::new(length),
            |copy| {
                user_copy::read(message, copy.bytes())?;
                let mut text = [0u8; 1025];
                let (consumed, used) =
                    packet::expand(copy.bytes(), offset, &mut text).map_err(|_| EINVAL)?;
                if used >= capacity {
                    return Err(ERANGE);
                }
                user_copy::write_c_string(destination.cast(), &text[..used])?;
                Ok(consumed as c_int)
            },
        )
    })()
}
