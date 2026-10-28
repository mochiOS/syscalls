//! Passive TCP transport state; syscall/FD and Capability policy stay outside.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpListenConfig {
    pub backlog: usize,
    pub local_mss: u16,
    pub send_capacity: usize,
    pub receive_capacity: usize,
    pub retransmit_timeout: u64,
    pub retry_limit: u8,
}

pub(super) struct Listener {
    pub(super) handle: u64,
    owner: u64,
    address: [u8; 4],
    pub(super) port: u16,
    config: TcpListenConfig,
    pending: Vec<u64>,
    ready: Vec<u64>,
}

impl TcpConnection {
    pub fn accept_syn(
        handle: u64,
        owner: u64,
        tuple: TcpTuple,
        initial_sequence: u32,
        config: TcpListenConfig,
        segment: &TcpSegment<'_>,
    ) -> Result<Self, TcpConnectionError> {
        validate_syn(tuple, segment)?;
        if handle == 0 || config.local_mss == 0 {
            return Err(TcpConnectionError::InvalidState);
        }
        if segment.payload.len() > config.receive_capacity {
            return Err(TcpConnectionError::ReceiveBufferFull);
        }
        let mut send_buffer = VecDeque::new();
        let mut receive_buffer = VecDeque::new();
        let mut outstanding = VecDeque::new();
        // Admit all storage before publishing a connection. Network traffic
        // must not turn receive admission into an allocation panic.
        send_buffer
            .try_reserve_exact(config.send_capacity)
            .map_err(|_| TcpConnectionError::Capacity)?;
        receive_buffer
            .try_reserve_exact(config.receive_capacity)
            .map_err(|_| TcpConnectionError::Capacity)?;
        outstanding
            .try_reserve_exact(1)
            .map_err(|_| TcpConnectionError::Capacity)?;
        let receive_next = segment
            .sequence
            .wrapping_add(1)
            .wrapping_add(segment.payload.len() as u32);
        outstanding.push_back(OutstandingSegment {
            sequence: initial_sequence,
            acknowledgment: receive_next,
            flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
            options: TcpOptions {
                maximum_segment_size: Some(config.local_mss),
            },
            payload: Vec::new(),
            sent_at: None,
            retries: 0,
        });
        // Accept/ACK SYN text, but defer application delivery until established.
        receive_buffer.extend(segment.payload.iter().copied());
        Ok(Self {
            handle,
            owner,
            tuple,
            state: TcpState::SynReceived,
            send_unacknowledged: initial_sequence,
            send_next: initial_sequence.wrapping_add(1),
            receive_next,
            peer_window: segment.window,
            peer_mss: segment.options.maximum_segment_size.unwrap_or(536).max(1),
            local_mss: config.local_mss,
            send_capacity: config.send_capacity,
            receive_capacity: config.receive_capacity,
            send_buffer,
            receive_buffer,
            outstanding,
            close_requested: false,
            retransmit_timeout: config.retransmit_timeout,
            retry_limit: config.retry_limit,
            time_wait_until: None,
        })
    }

    pub(super) fn passive_syn_ack(&self) -> TcpTransmit {
        TcpTransmit {
            sequence: self.send_unacknowledged,
            acknowledgment: self.receive_next,
            flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
            window: self.local_window(),
            options: TcpOptions {
                maximum_segment_size: Some(self.local_mss),
            },
            payload: Vec::new(),
            retransmission: true,
        }
    }

    pub(super) fn receive_passive(
        &mut self,
        segment: &TcpSegment<'_>,
        now: u64,
    ) -> Result<TcpReceiveResult, TcpConnectionError> {
        validate_segment(self.tuple, segment)?;
        if segment.flags & TCP_FLAG_RST != 0 {
            if segment.sequence != self.receive_next {
                return Err(TcpConnectionError::InvalidAcknowledgment);
            }
            self.abort();
            return Ok(TcpReceiveResult::Reset);
        }
        if segment.flags & TCP_FLAG_SYN != 0 {
            validate_syn(self.tuple, segment)?;
            return if segment
                .sequence
                .wrapping_add(1)
                .wrapping_add(self.receive_buffer.len() as u32)
                == self.receive_next
            {
                Ok(TcpReceiveResult::DuplicateSegment)
            } else {
                Err(TcpConnectionError::InvalidState)
            };
        }
        if !acceptable_sequence(self.receive_next, self.local_window(), segment) {
            return Ok(TcpReceiveResult::OutOfOrder);
        }
        if segment.flags & TCP_FLAG_ACK == 0 || segment.acknowledgment != self.send_next {
            return Err(TcpConnectionError::InvalidAcknowledgment);
        }
        self.acknowledge(segment.acknowledgment)?;
        self.state = TcpState::Established;
        self.peer_window = segment.window;
        let queued = self.receive_buffer.len();
        let mut input = *segment;
        // A peer may repeat its SYN text on the final ACK. Preserve only the
        // new suffix before applying the established stream's normal path.
        if sequence_before(input.sequence, self.receive_next) {
            let overlap = self.receive_next.wrapping_sub(input.sequence) as usize;
            let trim = overlap.min(input.payload.len());
            input.sequence = input.sequence.wrapping_add(trim as u32);
            input.payload = &input.payload[trim..];
        }
        let result = self.on_segment(&input, now)?;
        Ok(if queued != 0 {
            TcpReceiveResult::Acknowledge
        } else {
            result
        })
    }
}

fn validate_syn(tuple: TcpTuple, segment: &TcpSegment<'_>) -> Result<(), TcpConnectionError> {
    validate_segment(tuple, segment)?;
    if segment.flags & !TCP_FLAG_PSH != TCP_FLAG_SYN {
        Err(TcpConnectionError::InvalidState)
    } else {
        Ok(())
    }
}

fn validate_segment(tuple: TcpTuple, segment: &TcpSegment<'_>) -> Result<(), TcpConnectionError> {
    let header = TCP_HEADER_LEN
        + if segment.options.maximum_segment_size.is_some() {
            4
        } else {
            0
        };
    if tuple.local_port == 0
        || tuple.remote_port == 0
        || segment.source_port != tuple.remote_port
        || segment.destination_port != tuple.local_port
        || segment.flags & !TCP_SUPPORTED_FLAGS != 0
        || segment.payload.len() > usize::from(u16::MAX) - header
        || segment.urgent_pointer != 0
    {
        Err(TcpConnectionError::InvalidState)
    } else {
        Ok(())
    }
}

fn acceptable_sequence(next: u32, window: u16, segment: &TcpSegment<'_>) -> bool {
    let Some(length) = u32::try_from(segment.payload.len())
        .ok()
        .and_then(|length| length.checked_add(u32::from(segment.flags & TCP_FLAG_FIN != 0)))
    else {
        return false;
    };
    if window == 0 {
        return length == 0 && segment.sequence == next;
    }
    let inside = |sequence: u32| sequence.wrapping_sub(next) < u32::from(window);
    inside(segment.sequence) || length != 0 && inside(segment.sequence.wrapping_add(length - 1))
}

impl TcpConnectionTable {
    /// Reserve a transport listener. The owner is an opaque caller-supplied
    /// namespace selected by the service, never a claimed IPC sender identity.
    pub fn listen(
        &mut self,
        handle: u64,
        owner: u64,
        address: [u8; 4],
        port: u16,
        config: TcpListenConfig,
    ) -> Result<(), TcpConnectionError> {
        if port == 0 || handle == 0 || config.backlog == 0 || config.local_mss == 0 {
            return Err(TcpConnectionError::InvalidState);
        }
        if self.connections.len() + self.listeners.len() >= self.capacity
            || self.connections.iter().any(|c| c.handle == handle)
            || self.listeners.iter().any(|l| l.handle == handle)
        {
            return Err(TcpConnectionError::Capacity);
        }
        if self.listeners.iter().any(|l| {
            l.port == port && (l.address == address || l.address == [0; 4] || address == [0; 4])
        }) {
            return Err(TcpConnectionError::PortUnavailable);
        }
        self.listeners
            .try_reserve(1)
            .map_err(|_| TcpConnectionError::Capacity)?;
        self.listeners.push(Listener {
            handle,
            owner,
            address,
            port,
            config,
            pending: Vec::new(),
            ready: Vec::new(),
        });
        Ok(())
    }

    /// Admit a decoded SYN using an ISS chosen by the caller's entropy source.
    /// Keep embryonic and completed-but-unaccepted connections in one bounded
    /// backlog. A duplicate SYN reuses its original TCB/ISS without a new slot.
    pub fn receive_syn(
        &mut self,
        handle: u64,
        tuple: TcpTuple,
        segment: &TcpSegment<'_>,
        initial_sequence: u32,
    ) -> Result<u64, TcpConnectionError> {
        validate_syn(tuple, segment)?;
        self.prune_pending();
        if let Some(connection) = self.find_tuple_mut(tuple) {
            connection.on_segment(segment, 0)?;
            return Ok(connection.handle);
        }
        let listener = self
            .listeners
            .iter_mut()
            .find(|l| {
                l.port == tuple.local_port
                    && (l.address == tuple.local_address || l.address == [0; 4])
            })
            .ok_or(TcpConnectionError::NotFound)?;
        if listener.pending.len() >= listener.config.backlog {
            return Err(TcpConnectionError::Capacity);
        }
        listener
            .pending
            .try_reserve(1)
            .map_err(|_| TcpConnectionError::Capacity)?;
        let connection = TcpConnection::accept_syn(
            handle,
            listener.owner,
            tuple,
            initial_sequence,
            listener.config,
            segment,
        )?;
        let listener_handle = listener.handle;
        self.insert(connection)?;
        self.listeners
            .iter_mut()
            .find(|l| l.handle == listener_handle)
            .unwrap()
            .pending
            .push(handle);
        Ok(handle)
    }

    /// Process packets for retained transport connections. Handshake completion
    /// is queued in arrival order, independently of initial SYN order.
    pub fn receive_segment(
        &mut self,
        tuple: TcpTuple,
        segment: &TcpSegment<'_>,
        now: u64,
    ) -> Result<TcpReceiveResult, TcpConnectionError> {
        validate_segment(tuple, segment)?;
        let index = self
            .connections
            .iter()
            .position(|c| {
                c.tuple == tuple && !matches!(c.state, TcpState::Closed | TcpState::Reset)
            })
            .ok_or(TcpConnectionError::NotFound)?;
        let handle = self.connections[index].handle;
        let listener = self
            .listeners
            .iter()
            .position(|l| l.pending.contains(&handle) && !l.ready.contains(&handle));
        if let Some(index) = listener {
            // Reserve before a segment can commit ESTABLISHED. Allocation
            // failure leaves the SYN/ACK outstanding so its retry can recover.
            self.listeners[index]
                .ready
                .try_reserve(1)
                .map_err(|_| TcpConnectionError::Capacity)?;
        }
        let connection = &mut self.connections[index];
        let result = connection.on_segment(segment, now);
        if matches!(
            connection.state,
            TcpState::Established | TcpState::CloseWait
        ) {
            if let Some(index) = listener {
                self.listeners[index].ready.push(handle);
            }
        }
        result
    }

    pub fn accept(
        &mut self,
        listener: u64,
        owner: u64,
    ) -> Result<Option<(u64, TcpTuple)>, TcpConnectionError> {
        let index = self
            .listeners
            .iter()
            .position(|l| l.handle == listener)
            .ok_or(TcpConnectionError::NotFound)?;
        if self.listeners[index].owner != owner {
            return Err(TcpConnectionError::Ownership);
        }
        self.prune_pending();
        let listener = &mut self.listeners[index];
        let Some(&handle) = listener.ready.first() else {
            return Ok(None);
        };
        let connection = self
            .connections
            .iter()
            .find(|c| c.handle == handle)
            .unwrap();
        listener.ready.remove(0);
        listener.pending.retain(|id| *id != handle);
        Ok(Some((handle, connection.tuple)))
    }

    pub fn close_listener(&mut self, handle: u64, owner: u64) -> Result<(), TcpConnectionError> {
        let index = self
            .listeners
            .iter()
            .position(|l| l.handle == handle)
            .ok_or(TcpConnectionError::NotFound)?;
        if self.listeners[index].owner != owner {
            return Err(TcpConnectionError::Ownership);
        }
        let listener = self.listeners.swap_remove(index);
        self.connections
            .retain(|c| !listener.pending.contains(&c.handle));
        Ok(())
    }

    pub fn listener_count(&self) -> usize {
        self.listeners.len()
    }

    pub(super) fn prune_pending(&mut self) {
        // Retire only dead connections that have not been accepted. Accepted
        // owners retain their terminal observation until their own release.
        self.connections.retain(|connection| {
            !matches!(connection.state, TcpState::Reset | TcpState::Closed)
                || !self
                    .listeners
                    .iter()
                    .any(|listener| listener.pending.contains(&connection.handle))
        });
        for listener in &mut self.listeners {
            listener.pending.retain(|handle| {
                self.connections.iter().any(|c| {
                    c.handle == *handle && !matches!(c.state, TcpState::Reset | TcpState::Closed)
                })
            });
            listener
                .ready
                .retain(|handle| listener.pending.contains(handle));
        }
    }
}
