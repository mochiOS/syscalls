//! One retained socket description supplies both the payload and its source.
use super::*;
use mochios_posix_protocol::socket as wire;

pub(super) fn receive(
    entry: FdEntry,
    buffer: *mut c_void,
    length: usize,
    flags: c_int,
    address: *mut c_void,
    address_length: *mut u32,
) -> Result<isize, c_int> {
    if !entry.handle.kind.is_socket() {
        return Err(mochios_posix_client::newlib_errno::from_status(-88));
    }
    if address.is_null() {
        // The length pointer is ignored when no source address is requested.
        return socket::message_entry(entry, buffer as u64, length, flags, false);
    }
    let capacity = socket_memory::read_length(address_length)? as usize;
    let mut native = [0; mochios_posix_client::socket::MAX_SOCKADDR_LEN];
    let (count, required) = if socket::is_datagram(entry)? {
        let record = socket_record::io(entry, buffer as u64, length, flags, false)?;
        let source =
            wire::Address::decode(&record.source[..record.source_length]).map_err(|_| EIO)?;
        let required =
            mochios_posix_client::socket::encode_sockaddr(source, &mut native).map_err(|_| EIO)?;
        (record.count, required)
    } else {
        // Query before consuming data; a stream's peer is immutable. Never
        // re-resolve the FD after a callback could close and reuse its number.
        let mut required = native.len() as u32;
        socket::socket_name_entry(entry, native.as_mut_ptr().cast(), &mut required, true)?;
        let count = socket::message_entry(entry, buffer as u64, length, flags, false)?;
        (count, required as usize)
    };
    socket_memory::write_output(
        address,
        address_length,
        &native[..capacity.min(required)],
        required as u32,
    )?;
    Ok(count)
}
