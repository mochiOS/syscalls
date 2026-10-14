//! Synchronous fault delivery. No native exception or handler pointers cross IPC.

use super::*;

pub const DELIVERY_LEN: usize = SIGNAL_DELIVERY_LEN + 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub signal: SignalDelivery,
    /// DEFAULT also covers ignored or blocked synchronous faults. Such faults
    /// must not be retried forever without running a handler.
    pub disposition: u32,
}

pub fn encode(delivery: Delivery, output: &mut [u8]) -> Result<(), ProtocolError> {
    if output.len() < DELIVERY_LEN {
        return Err(ProtocolError::BufferTooSmall);
    }
    if !matches!(delivery.signal.signal, SIGNAL_BUS | SIGNAL_SEGV)
        || delivery.signal.token == 0
        || !matches!(
            delivery.disposition,
            SIGNAL_DISPOSITION_DEFAULT | SIGNAL_DISPOSITION_CAUGHT
        )
    {
        return Err(ProtocolError::InvalidLength);
    }
    encode_signal_delivery(delivery.signal, output)?;
    put_u32(output, SIGNAL_DELIVERY_LEN, delivery.disposition);
    put_u32(output, SIGNAL_DELIVERY_LEN + 4, 0);
    Ok(())
}

pub fn decode(input: &[u8]) -> Result<Delivery, ProtocolError> {
    if input.len() != DELIVERY_LEN || get_u32(input, SIGNAL_DELIVERY_LEN + 4) != 0 {
        return Err(ProtocolError::InvalidLength);
    }
    let delivery = Delivery {
        signal: decode_signal_delivery(&input[..SIGNAL_DELIVERY_LEN])?,
        disposition: get_u32(input, SIGNAL_DELIVERY_LEN),
    };
    encode(delivery, &mut [0; DELIVERY_LEN])?;
    Ok(delivery)
}
