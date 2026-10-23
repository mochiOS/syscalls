/// Atomic pipe write size advertised by the newlib headers. This is POSIX
/// policy, not a constant interpreted by the kernel stream mechanism.
pub const PIPE_BUF: usize = mochios_posix_protocol::PIPE_BUF;

#[derive(Debug, PartialEq, Eq)]
pub enum WriteError<E> {
    InvalidResult,
    Io(E),
}

/// Small writes request one all-or-none native operation. Larger blocking
/// writes continue after native short transfers; nonblocking writes return
/// available progress immediately. An error after progress returns that prefix.
pub fn write<E>(
    length: usize,
    nonblocking: bool,
    mut io: impl FnMut(usize, usize, bool) -> Result<usize, E>,
) -> Result<usize, WriteError<E>> {
    let complete = length <= PIPE_BUF;
    let mut written = 0;
    loop {
        let remaining = length - written;
        let count = match io(written, remaining, complete) {
            Ok(count) if count <= remaining && (!complete || count == remaining) => count,
            Ok(_) => {
                return if written == 0 {
                    Err(WriteError::InvalidResult)
                } else {
                    Ok(written)
                };
            }
            Err(error) => {
                return if written == 0 {
                    Err(WriteError::Io(error))
                } else {
                    Ok(written)
                };
            }
        };
        written += count;
        if complete || nonblocking || count == 0 || written == length {
            return Ok(written);
        }
    }
}
