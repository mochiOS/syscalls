//! TCP receive routing shared by device and loopback packet paths.
//! The caller validates IP routing/checksums before passing a decoded segment.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpDispatch {
    /// Private transport label, never a native Handle or caller authority.
    pub connection: Option<u64>,
    pub event: Option<TcpReceiveResult>,
    pub reply: Option<TcpTransmit>,
}

impl TcpDispatch {
    fn silent(connection: Option<u64>) -> Self {
        Self {
            connection,
            event: None,
            reply: None,
        }
    }
}

impl TcpConnectionTable {
    /// Route one decoded segment, admit passive opens and form immediate
    /// control replies. Retransmissions still use `poll_transmit`/`tick`.
    /// `entropy` is called only for an admissible, new listener SYN. Failure
    /// leaves the listener intact and never substitutes a predictable ISS.
    pub fn receive_packet(
        &mut self,
        tuple: TcpTuple,
        segment: &TcpSegment<'_>,
        now: u64,
        entropy: impl FnOnce() -> Option<u64>,
    ) -> Result<TcpDispatch, TcpConnectionError> {
        passive::validate_segment(tuple, segment)?;
        // TCP never responds to unspecified, multicast or limited-broadcast
        // addresses. Interface-specific directed broadcasts are rejected by
        // the IP input layer, which knows the subnet mask.
        if [tuple.local_address, tuple.remote_address]
            .iter()
            .any(|address| address[0] == 0 || address[0] >= 224)
        {
            return Err(TcpConnectionError::InvalidState);
        }
        if let Some(connection) = self.find_tuple_mut(tuple) {
            let handle = connection.handle;
            let state = connection.state;
            let mut dispatch = TcpDispatch::silent(Some(handle));
            let rst = segment.flags & TCP_FLAG_RST != 0;
            let syn = segment.flags & TCP_FLAG_SYN != 0;
            let ack = segment.flags & TCP_FLAG_ACK != 0;

            if state == TcpState::SynSent {
                // Invalid ACKs must not reset our TCB, and resets must never
                // elicit another reset. A bare ACK cannot establish a stream.
                if ack && segment.acknowledgment != connection.send_next {
                    dispatch.reply = (!rst).then(|| reset(segment));
                    return Ok(dispatch);
                }
                if !rst && !syn {
                    return Ok(dispatch);
                }
            } else {
                if rst && segment.sequence != connection.receive_next {
                    // An in-window non-exact reset gets a challenge ACK;
                    // out-of-window resets are silently ignored.
                    if segment.sequence.wrapping_sub(connection.receive_next)
                        < u32::from(connection.local_window())
                    {
                        dispatch.reply = Some(plain_ack(connection));
                    }
                    return Ok(dispatch);
                }
                if !rst {
                    let duplicate_syn = state == TcpState::SynReceived
                        && segment.flags & !TCP_FLAG_PSH == TCP_FLAG_SYN
                        && segment
                            .sequence
                            .wrapping_add(1)
                            .wrapping_add(connection.receive_buffer.len() as u32)
                            == connection.receive_next;
                    let duplicate_syn_ack = state == TcpState::Established
                        && segment.flags == TCP_FLAG_SYN | TCP_FLAG_ACK
                        && segment.sequence.wrapping_add(1) == connection.receive_next
                        && segment.acknowledgment == connection.send_unacknowledged
                        && segment.payload.is_empty();
                    if syn && !duplicate_syn && !duplicate_syn_ack
                        || !syn
                            && !passive::acceptable_sequence(
                                connection.receive_next,
                                connection.local_window(),
                                segment,
                            )
                    {
                        dispatch.reply = Some(plain_ack(connection));
                        dispatch.event = Some(TcpReceiveResult::OutOfOrder);
                        return Ok(dispatch);
                    }
                    if !syn && !ack {
                        return Ok(dispatch);
                    }
                }
            }

            // Keep completed passive opens in the table's accept queue. Going
            // directly to the TCB would bypass that completion bookkeeping.
            let received = self.receive_segment(tuple, segment, now);
            let connection = self
                .connections
                .iter()
                .find(|connection| connection.handle == handle)
                .ok_or(TcpConnectionError::NotFound)?;
            match received {
                Ok(event) => {
                    dispatch.event = Some(event);
                    if matches!(
                        event,
                        TcpReceiveResult::Acknowledge
                            | TcpReceiveResult::DuplicateSegment
                            | TcpReceiveResult::OutOfOrder
                    ) {
                        dispatch.reply = Some(if state == TcpState::SynReceived && syn {
                            connection.passive_syn_ack()
                        } else {
                            plain_ack(connection)
                        });
                    }
                }
                Err(TcpConnectionError::InvalidAcknowledgment) => {
                    dispatch.reply = if rst {
                        None
                    } else if matches!(state, TcpState::SynSent | TcpState::SynReceived) {
                        ack.then(|| reset(segment))
                    } else {
                        Some(plain_ack(connection))
                    };
                }
                Err(error) => return Err(error),
            }
            return Ok(dispatch);
        }

        let mut dispatch = TcpDispatch::silent(None);
        if segment.flags & TCP_FLAG_RST != 0 {
            return Ok(dispatch);
        }
        if self.matching_listener(tuple).is_none() || segment.flags & TCP_FLAG_ACK != 0 {
            dispatch.reply = Some(reset(segment));
            return Ok(dispatch);
        }
        if segment.flags & !TCP_FLAG_PSH != TCP_FLAG_SYN {
            return Ok(dispatch);
        }
        // Check limits before drawing entropy; backlog floods and duplicate
        // SYNs must not invoke the entropy source for every received packet.
        self.admit_syn(tuple, segment.payload.len())?;
        let random = entropy().ok_or(TcpConnectionError::EntropyUnavailable)?;
        let handle = self.allocate_handle(random.rotate_left(17))?;
        self.receive_syn(handle, tuple, segment, (random >> 32) as u32)?;
        let connection = self
            .find_tuple_mut(tuple)
            .ok_or(TcpConnectionError::NotFound)?;
        dispatch.connection = Some(handle);
        dispatch.event = Some(TcpReceiveResult::Acknowledge);
        dispatch.reply = connection.poll_transmit(now)?;
        Ok(dispatch)
    }
}

fn plain_ack(connection: &TcpConnection) -> TcpTransmit {
    TcpTransmit {
        sequence: connection.send_next,
        acknowledgment: connection.receive_next,
        flags: TCP_FLAG_ACK,
        window: connection.local_window(),
        options: TcpOptions::default(),
        payload: Vec::new(),
        retransmission: false,
    }
}

fn reset(segment: &TcpSegment<'_>) -> TcpTransmit {
    let ack = segment.flags & TCP_FLAG_ACK != 0;
    TcpTransmit {
        sequence: if ack { segment.acknowledgment } else { 0 },
        acknowledgment: if ack {
            0
        } else {
            segment
                .sequence
                .wrapping_add(segment.payload.len() as u32)
                .wrapping_add(u32::from(segment.flags & TCP_FLAG_SYN != 0))
                .wrapping_add(u32::from(segment.flags & TCP_FLAG_FIN != 0))
        },
        flags: TCP_FLAG_RST | if ack { 0 } else { TCP_FLAG_ACK },
        window: 0,
        options: TcpOptions::default(),
        payload: Vec::new(),
        retransmission: false,
    }
}
