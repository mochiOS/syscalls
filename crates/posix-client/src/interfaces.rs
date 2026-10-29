//! Interface observations through an explicitly delegated network endpoint.
use crate::{ClientError, ObjectHandles, ObjectTransport};
use mochios_net_device_protocol::interfaces as wire;
pub use mochios_net_device_protocol::interfaces::{Address, MAX_REPLY, Snapshot};
pub fn snapshot<'a, T: ObjectTransport>(
    transport: &T,
    buffer: &'a mut [u8],
) -> Result<Snapshot<'a>, ClientError<T::Error>> {
    // Reserve the complete bounded reply before sending. A short destination
    // must not leave the peer trying to reply to an undersized IPC buffer.
    if buffer.len() < MAX_REPLY {
        return Err(ClientError::ResponseTooLarge);
    }
    let mut attached = ObjectHandles::new();
    let borrowed = attached.clone();
    let outcome = transport
        .call_with_handles(&wire::request(wire::SNAPSHOT), buffer, &mut attached)
        .map_err(ClientError::Transport);
    let empty = attached.is_empty();
    crate::drain_received_handles(&mut attached, &borrowed, |h| {
        transport.close_received_handle(h)
    });
    let n = outcome?;
    if !empty {
        return Err(ClientError::MismatchedResponse);
    }
    let result = wire::decode(buffer.get(..n).ok_or(ClientError::MismatchedResponse)?)
        .map_err(|_| ClientError::MismatchedResponse)?;
    if result.status != 0 {
        return Err(ClientError::Remote(result.status));
    }
    Ok(result)
}
pub fn configuration(snapshot: Snapshot<'_>) -> crate::netdb::Configuration {
    let mut result = crate::netdb::Configuration {
        ipv4: false,
        ipv6: false,
    };
    for record in snapshot.records() {
        if record.flags & wire::LOOPBACK != 0 {
            continue;
        }
        for address in record.addresses() {
            match address {
                wire::Address::V4 { bytes, flags, .. }
                    if flags & wire::USABLE != 0 && bytes != [0; 4] && bytes[0] != 127 =>
                {
                    result.ipv4 = true
                }
                wire::Address::V6 { bytes, flags, .. }
                    if flags & wire::USABLE != 0
                        && bytes != [0; 16]
                        && bytes != [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] =>
                {
                    result.ipv6 = true
                }
                _ => {}
            }
        }
    }
    result
}
