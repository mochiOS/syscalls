use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::PacketError;

pub const TCP_PROTOCOL: u8 = 6;
pub const TCP_HEADER_LEN: usize = 20;
pub const TCP_FLAG_FIN: u16 = 0x001;
pub const TCP_FLAG_SYN: u16 = 0x002;
pub const TCP_FLAG_RST: u16 = 0x004;
pub const TCP_FLAG_PSH: u16 = 0x008;
pub const TCP_FLAG_ACK: u16 = 0x010;
pub const TCP_FLAG_URG: u16 = 0x020;
const TCP_SUPPORTED_FLAGS: u16 =
    TCP_FLAG_FIN | TCP_FLAG_SYN | TCP_FLAG_RST | TCP_FLAG_PSH | TCP_FLAG_ACK;
pub const TCP_EPHEMERAL_START: u16 = 49_152;
pub const TCP_EPHEMERAL_END: u16 = 65_535;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpOptions {
    pub maximum_segment_size: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: u16,
    pub window: u16,
    pub urgent_pointer: u16,
    pub options: TcpOptions,
    pub payload: &'a [u8],
}

impl<'a> TcpSegment<'a> {
    pub fn encode(
        self,
        source_address: [u8; 4],
        destination_address: [u8; 4],
        out: &mut [u8],
    ) -> Result<usize, PacketError> {
        if self.flags & !TCP_SUPPORTED_FLAGS != 0 || self.urgent_pointer != 0 {
            return Err(PacketError::Unsupported);
        }
        let option_length = if self.options.maximum_segment_size.is_some() {
            4
        } else {
            0
        };
        let header_length = TCP_HEADER_LEN + option_length;
        let total = header_length
            .checked_add(self.payload.len())
            .ok_or(PacketError::InvalidLength)?;
        let total_u16 = u16::try_from(total).map_err(|_| PacketError::InvalidLength)?;
        if out.len() < total {
            return Err(PacketError::Truncated);
        }
        out[..header_length].fill(0);
        out[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        out[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
        out[4..8].copy_from_slice(&self.sequence.to_be_bytes());
        out[8..12].copy_from_slice(&self.acknowledgment.to_be_bytes());
        out[12] = u8::try_from(header_length / 4).map_err(|_| PacketError::InvalidLength)? << 4;
        out[13] = (self.flags & 0xff) as u8;
        if self.flags & 0x100 != 0 {
            out[12] |= 1;
        }
        out[14..16].copy_from_slice(&self.window.to_be_bytes());
        out[18..20].copy_from_slice(&self.urgent_pointer.to_be_bytes());
        if let Some(mss) = self.options.maximum_segment_size {
            out[20] = 2;
            out[21] = 4;
            out[22..24].copy_from_slice(&mss.to_be_bytes());
        }
        out[header_length..total].copy_from_slice(self.payload);
        let checksum = tcp_checksum(
            source_address,
            destination_address,
            total_u16,
            &out[..total],
        );
        out[16..18].copy_from_slice(&checksum.to_be_bytes());
        Ok(total)
    }

    pub fn decode(
        source_address: [u8; 4],
        destination_address: [u8; 4],
        packet: &'a [u8],
    ) -> Result<Self, PacketError> {
        if packet.len() < TCP_HEADER_LEN {
            return Err(PacketError::Truncated);
        }
        let data_offset = usize::from(packet[12] >> 4);
        if !(5..=15).contains(&data_offset) {
            return Err(PacketError::InvalidHeader);
        }
        let header_length = data_offset
            .checked_mul(4)
            .ok_or(PacketError::InvalidLength)?;
        if header_length > packet.len() {
            return Err(PacketError::Truncated);
        }
        let length = u16::try_from(packet.len()).map_err(|_| PacketError::InvalidLength)?;
        if tcp_checksum(source_address, destination_address, length, packet) != 0 {
            return Err(PacketError::InvalidChecksum);
        }
        let flags = u16::from(packet[13]) | (u16::from(packet[12] & 1) << 8);
        let urgent_pointer = read_u16(packet, 18);
        if flags & !TCP_SUPPORTED_FLAGS != 0 || urgent_pointer != 0 {
            return Err(PacketError::Unsupported);
        }
        Ok(Self {
            source_port: read_u16(packet, 0),
            destination_port: read_u16(packet, 2),
            sequence: read_u32(packet, 4),
            acknowledgment: read_u32(packet, 8),
            flags,
            window: read_u16(packet, 14),
            urgent_pointer,
            options: parse_options(&packet[TCP_HEADER_LEN..header_length])?,
            payload: &packet[header_length..],
        })
    }
}

fn parse_options(options: &[u8]) -> Result<TcpOptions, PacketError> {
    let mut parsed = TcpOptions::default();
    let mut offset = 0usize;
    while offset < options.len() {
        match options[offset] {
            0 => break,
            1 => offset += 1,
            kind => {
                let length =
                    usize::from(*options.get(offset + 1).ok_or(PacketError::InvalidHeader)?);
                if length < 2 {
                    return Err(PacketError::InvalidHeader);
                }
                let end = offset
                    .checked_add(length)
                    .ok_or(PacketError::InvalidLength)?;
                let body = options
                    .get(offset + 2..end)
                    .ok_or(PacketError::InvalidHeader)?;
                if kind == 2 {
                    if length != 4 {
                        return Err(PacketError::InvalidHeader);
                    }
                    parsed.maximum_segment_size = Some(u16::from_be_bytes([body[0], body[1]]));
                }
                offset = end;
            }
        }
    }
    Ok(parsed)
}

fn tcp_checksum(source: [u8; 4], destination: [u8; 4], tcp_length: u16, packet: &[u8]) -> u16 {
    let mut pseudo = [0u8; 12];
    pseudo[..4].copy_from_slice(&source);
    pseudo[4..8].copy_from_slice(&destination);
    pseudo[9] = TCP_PROTOCOL;
    pseudo[10..12].copy_from_slice(&tcp_length.to_be_bytes());
    let mut sum = partial_checksum(&pseudo) + partial_checksum(packet);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn partial_checksum(bytes: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        sum = sum.saturating_add(u32::from(u16::from_be_bytes([pair[0], pair[1]])));
    }
    if let Some(byte) = chunks.remainder().first() {
        sum = sum.saturating_add(u32::from(*byte) << 8);
    }
    sum
}

fn read_u16(packet: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([packet[offset], packet[offset + 1]])
}

fn read_u32(packet: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        packet[offset],
        packet[offset + 1],
        packet[offset + 2],
        packet[offset + 3],
    ])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
    Reset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpTuple {
    pub local_address: [u8; 4],
    pub local_port: u16,
    pub remote_address: [u8; 4],
    pub remote_port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpTransmit {
    pub sequence: u32,
    pub acknowledgment: u32,
    pub flags: u16,
    pub window: u16,
    pub options: TcpOptions,
    pub payload: Vec<u8>,
    pub retransmission: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpReceiveResult {
    Accepted,
    Acknowledge,
    DuplicateAck,
    DuplicateSegment,
    OutOfOrder,
    Reset,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpConnectionError {
    InvalidState,
    InvalidAcknowledgment,
    SendBufferFull,
    ReceiveBufferFull,
    Timeout,
    RetryLimit,
    ConnectionReset,
    Capacity,
    PortUnavailable,
    Ownership,
    NotFound,
}

#[derive(Clone, Debug)]
struct OutstandingSegment {
    sequence: u32,
    acknowledgment: u32,
    flags: u16,
    options: TcpOptions,
    payload: Vec<u8>,
    sent_at: Option<u64>,
    retries: u8,
}

impl OutstandingSegment {
    fn sequence_end(&self) -> u32 {
        self.sequence
            .wrapping_add(self.payload.len() as u32)
            .wrapping_add(u32::from(self.flags & TCP_FLAG_SYN != 0))
            .wrapping_add(u32::from(self.flags & TCP_FLAG_FIN != 0))
    }
}

pub struct TcpConnection {
    pub handle: u64,
    pub owner: u64,
    pub tuple: TcpTuple,
    pub state: TcpState,
    pub send_unacknowledged: u32,
    pub send_next: u32,
    pub receive_next: u32,
    pub peer_window: u16,
    pub peer_mss: u16,
    local_mss: u16,
    send_capacity: usize,
    receive_capacity: usize,
    send_buffer: VecDeque<u8>,
    receive_buffer: VecDeque<u8>,
    outstanding: VecDeque<OutstandingSegment>,
    close_requested: bool,
    retransmit_timeout: u64,
    retry_limit: u8,
    time_wait_until: Option<u64>,
}

impl TcpConnection {
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        handle: u64,
        owner: u64,
        tuple: TcpTuple,
        initial_sequence: u32,
        local_mss: u16,
        send_capacity: usize,
        receive_capacity: usize,
        retransmit_timeout: u64,
        retry_limit: u8,
    ) -> Self {
        let syn = OutstandingSegment {
            sequence: initial_sequence,
            acknowledgment: 0,
            flags: TCP_FLAG_SYN,
            options: TcpOptions {
                maximum_segment_size: Some(local_mss),
            },
            payload: Vec::new(),
            sent_at: None,
            retries: 0,
        };
        let mut outstanding = VecDeque::with_capacity(1);
        outstanding.push_back(syn);
        Self {
            handle,
            owner,
            tuple,
            state: TcpState::SynSent,
            send_unacknowledged: initial_sequence,
            send_next: initial_sequence.wrapping_add(1),
            receive_next: 0,
            peer_window: 0,
            peer_mss: local_mss,
            local_mss,
            send_capacity,
            receive_capacity,
            send_buffer: VecDeque::with_capacity(send_capacity),
            receive_buffer: VecDeque::with_capacity(receive_capacity),
            outstanding,
            close_requested: false,
            retransmit_timeout,
            retry_limit,
            time_wait_until: None,
        }
    }

    pub fn queue_send(&mut self, bytes: &[u8]) -> Result<(), TcpConnectionError> {
        if self.state != TcpState::Established {
            return Err(TcpConnectionError::InvalidState);
        }
        let in_flight = self.outstanding.iter().fold(0usize, |total, segment| {
            total.saturating_add(segment.payload.len())
        });
        if in_flight
            .saturating_add(self.send_buffer.len())
            .saturating_add(bytes.len())
            > self.send_capacity
        {
            return Err(TcpConnectionError::SendBufferFull);
        }
        self.send_buffer.extend(bytes.iter().copied());
        Ok(())
    }

    pub fn request_close(&mut self) -> Result<(), TcpConnectionError> {
        if !matches!(self.state, TcpState::Established | TcpState::CloseWait) {
            return Err(TcpConnectionError::InvalidState);
        }
        self.close_requested = true;
        Ok(())
    }

    pub fn acknowledgment(&self) -> TcpTransmit {
        TcpTransmit {
            sequence: self.send_next,
            acknowledgment: self.receive_next,
            flags: TCP_FLAG_ACK,
            window: self.local_window(),
            options: TcpOptions::default(),
            payload: Vec::new(),
            retransmission: false,
        }
    }

    pub fn abort(&mut self) {
        self.state = TcpState::Reset;
        self.outstanding.clear();
        self.send_buffer.clear();
        self.receive_buffer.clear();
    }

    pub fn poll_transmit(&mut self, now: u64) -> Result<Option<TcpTransmit>, TcpConnectionError> {
        let local_window = self.local_window();
        if let Some(segment) = self.outstanding.front_mut() {
            if let Some(sent_at) = segment.sent_at {
                let delay = self
                    .retransmit_timeout
                    .saturating_mul(1u64 << u32::from(segment.retries.min(20)));
                if now.saturating_sub(sent_at) < delay {
                    return Ok(None);
                }
                if segment.retries >= self.retry_limit {
                    self.state = TcpState::Reset;
                    return Err(TcpConnectionError::RetryLimit);
                }
                segment.retries = segment.retries.saturating_add(1);
                segment.sent_at = Some(now);
                return Ok(Some(transmit_from(segment, local_window, true)));
            }
            segment.sent_at = Some(now);
            return Ok(Some(transmit_from(segment, local_window, false)));
        }

        if self.state == TcpState::Established && !self.send_buffer.is_empty() {
            if self.peer_window == 0 {
                return Ok(None);
            }
            let maximum = usize::from(self.local_mss.min(self.peer_mss).min(self.peer_window));
            if maximum == 0 {
                return Ok(None);
            }
            let length = maximum.min(self.send_buffer.len());
            let mut payload = Vec::with_capacity(length);
            for _ in 0..length {
                if let Some(byte) = self.send_buffer.pop_front() {
                    payload.push(byte);
                }
            }
            let segment = OutstandingSegment {
                sequence: self.send_next,
                acknowledgment: self.receive_next,
                flags: TCP_FLAG_ACK | TCP_FLAG_PSH,
                options: TcpOptions::default(),
                payload,
                sent_at: Some(now),
                retries: 0,
            };
            self.send_next = segment.sequence_end();
            let transmit = transmit_from(&segment, self.local_window(), false);
            self.outstanding.push_back(segment);
            return Ok(Some(transmit));
        }

        if self.close_requested
            && self.send_buffer.is_empty()
            && self.outstanding.is_empty()
            && matches!(self.state, TcpState::Established | TcpState::CloseWait)
        {
            let flags = TCP_FLAG_FIN | TCP_FLAG_ACK;
            let segment = OutstandingSegment {
                sequence: self.send_next,
                acknowledgment: self.receive_next,
                flags,
                options: TcpOptions::default(),
                payload: Vec::new(),
                sent_at: Some(now),
                retries: 0,
            };
            self.send_next = self.send_next.wrapping_add(1);
            self.state = if self.state == TcpState::CloseWait {
                TcpState::LastAck
            } else {
                TcpState::FinWait1
            };
            let transmit = transmit_from(&segment, self.local_window(), false);
            self.outstanding.push_back(segment);
            return Ok(Some(transmit));
        }
        Ok(None)
    }

    pub fn on_segment(
        &mut self,
        segment: &TcpSegment<'_>,
        now: u64,
    ) -> Result<TcpReceiveResult, TcpConnectionError> {
        if segment.flags & TCP_FLAG_RST != 0 {
            if (self.state == TcpState::SynSent
                && (segment.flags & TCP_FLAG_ACK == 0 || segment.acknowledgment != self.send_next))
                || (self.state != TcpState::SynSent && segment.sequence != self.receive_next)
            {
                return Err(TcpConnectionError::InvalidAcknowledgment);
            }
            self.state = TcpState::Reset;
            self.outstanding.clear();
            self.send_buffer.clear();
            return Ok(TcpReceiveResult::Reset);
        }
        if self.state == TcpState::SynSent {
            if segment.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK) != TCP_FLAG_SYN | TCP_FLAG_ACK
                || segment.acknowledgment != self.send_next
            {
                return Err(TcpConnectionError::InvalidAcknowledgment);
            }
            self.acknowledge(segment.acknowledgment)?;
            self.receive_next = segment.sequence.wrapping_add(1);
            self.peer_window = segment.window;
            if let Some(mss) = segment.options.maximum_segment_size {
                self.peer_mss = mss.max(1);
            }
            self.state = TcpState::Established;
            return Ok(TcpReceiveResult::Acknowledge);
        }
        if !matches!(
            self.state,
            TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::LastAck
                | TcpState::TimeWait
        ) {
            return Err(TcpConnectionError::InvalidState);
        }
        if segment.flags & TCP_FLAG_SYN != 0 {
            return Err(TcpConnectionError::InvalidState);
        }
        if segment.flags & TCP_FLAG_ACK == 0 {
            return Err(TcpConnectionError::InvalidAcknowledgment);
        }
        if segment.payload.is_empty()
            && segment.flags & TCP_FLAG_FIN == 0
            && segment.sequence != self.receive_next
        {
            return Ok(if sequence_before(segment.sequence, self.receive_next) {
                TcpReceiveResult::DuplicateSegment
            } else {
                TcpReceiveResult::OutOfOrder
            });
        }

        let mut result = TcpReceiveResult::Accepted;
        if segment.flags & TCP_FLAG_ACK != 0 {
            if segment.acknowledgment == self.send_unacknowledged {
                result = TcpReceiveResult::DuplicateAck;
            } else {
                self.acknowledge(segment.acknowledgment)?;
                if self.state == TcpState::FinWait1 && segment.acknowledgment == self.send_next {
                    self.state = TcpState::FinWait2;
                } else if self.state == TcpState::LastAck
                    && segment.acknowledgment == self.send_next
                {
                    self.state = TcpState::Closed;
                    return Ok(TcpReceiveResult::Closed);
                }
            }
            self.peer_window = segment.window;
        }

        if !segment.payload.is_empty() {
            if segment.sequence == self.receive_next {
                if self
                    .receive_buffer
                    .len()
                    .saturating_add(segment.payload.len())
                    > self.receive_capacity
                {
                    return Err(TcpConnectionError::ReceiveBufferFull);
                }
                self.receive_buffer.extend(segment.payload.iter().copied());
                self.receive_next = self.receive_next.wrapping_add(segment.payload.len() as u32);
                result = TcpReceiveResult::Acknowledge;
            } else if sequence_before(segment.sequence, self.receive_next) {
                result = TcpReceiveResult::DuplicateSegment;
            } else {
                result = TcpReceiveResult::OutOfOrder;
            }
        }

        if segment.flags & TCP_FLAG_FIN != 0 {
            let fin_sequence = segment.sequence.wrapping_add(segment.payload.len() as u32);
            if fin_sequence != self.receive_next {
                return Ok(TcpReceiveResult::OutOfOrder);
            }
            self.receive_next = self.receive_next.wrapping_add(1);
            if matches!(self.state, TcpState::FinWait1 | TcpState::FinWait2) {
                self.state = TcpState::TimeWait;
                self.time_wait_until = Some(now.saturating_add(30_000));
            } else if self.state == TcpState::Established {
                self.state = TcpState::CloseWait;
            }
            result = TcpReceiveResult::Acknowledge;
        }
        Ok(result)
    }

    fn acknowledge(&mut self, acknowledgment: u32) -> Result<(), TcpConnectionError> {
        if sequence_before(acknowledgment, self.send_unacknowledged)
            || sequence_after(acknowledgment, self.send_next)
        {
            return Err(TcpConnectionError::InvalidAcknowledgment);
        }
        self.send_unacknowledged = acknowledgment;
        while self
            .outstanding
            .front()
            .is_some_and(|segment| !sequence_after(segment.sequence_end(), acknowledgment))
        {
            self.outstanding.pop_front();
        }
        Ok(())
    }

    pub fn receive(&mut self, out: &mut [u8]) -> usize {
        let length = out.len().min(self.receive_buffer.len());
        for byte in out.iter_mut().take(length) {
            if let Some(value) = self.receive_buffer.pop_front() {
                *byte = value;
            }
        }
        length
    }

    pub fn received_len(&self) -> usize {
        self.receive_buffer.len()
    }

    pub fn queued_send_len(&self) -> usize {
        self.send_buffer.len()
    }

    pub fn has_unacknowledged(&self) -> bool {
        !self.outstanding.is_empty()
    }

    pub fn local_window(&self) -> u16 {
        u16::try_from(
            self.receive_capacity
                .saturating_sub(self.receive_buffer.len()),
        )
        .unwrap_or(u16::MAX)
    }

    pub fn tick(&mut self, now: u64) -> TcpReceiveResult {
        if self.state == TcpState::TimeWait
            && self.time_wait_until.is_some_and(|until| now >= until)
        {
            self.state = TcpState::Closed;
            return TcpReceiveResult::Closed;
        }
        TcpReceiveResult::Accepted
    }
}

fn transmit_from(segment: &OutstandingSegment, window: u16, retransmission: bool) -> TcpTransmit {
    TcpTransmit {
        sequence: segment.sequence,
        acknowledgment: segment.acknowledgment,
        flags: segment.flags,
        window,
        options: segment.options,
        payload: segment.payload.clone(),
        retransmission,
    }
}

fn sequence_before(left: u32, right: u32) -> bool {
    (left.wrapping_sub(right) as i32) < 0
}

fn sequence_after(left: u32, right: u32) -> bool {
    sequence_before(right, left)
}

pub struct TcpConnectionTable {
    connections: Vec<TcpConnection>,
    capacity: usize,
}

impl TcpConnectionTable {
    pub fn new(capacity: usize) -> Self {
        Self {
            connections: Vec::with_capacity(capacity),
            capacity,
        }
    }

    pub fn allocate_port(&self, seed: u16) -> Result<u16, TcpConnectionError> {
        let range = u32::from(TCP_EPHEMERAL_END) - u32::from(TCP_EPHEMERAL_START) + 1;
        let first = TCP_EPHEMERAL_START + (u32::from(seed) % range) as u16;
        for offset in 0..range {
            let port = TCP_EPHEMERAL_START
                + ((u32::from(first - TCP_EPHEMERAL_START) + offset) % range) as u16;
            if !self.connections.iter().any(|connection| {
                connection.tuple.local_port == port && connection.state != TcpState::Closed
            }) {
                return Ok(port);
            }
        }
        Err(TcpConnectionError::PortUnavailable)
    }

    pub fn insert(&mut self, connection: TcpConnection) -> Result<(), TcpConnectionError> {
        if self.connections.len() >= self.capacity {
            return Err(TcpConnectionError::Capacity);
        }
        if self.connections.iter().any(|existing| {
            existing.handle == connection.handle || existing.tuple == connection.tuple
        }) {
            return Err(TcpConnectionError::Capacity);
        }
        self.connections.push(connection);
        Ok(())
    }

    pub fn get_mut(
        &mut self,
        handle: u64,
        owner: u64,
    ) -> Result<&mut TcpConnection, TcpConnectionError> {
        let connection = self
            .connections
            .iter_mut()
            .find(|connection| connection.handle == handle)
            .ok_or(TcpConnectionError::NotFound)?;
        if connection.owner != owner {
            return Err(TcpConnectionError::Ownership);
        }
        Ok(connection)
    }

    pub fn find_tuple_mut(&mut self, tuple: TcpTuple) -> Option<&mut TcpConnection> {
        self.connections
            .iter_mut()
            .find(|connection| connection.tuple == tuple && connection.state != TcpState::Closed)
    }

    pub fn allocate_handle(&self, seed: u64) -> Result<u64, TcpConnectionError> {
        let mut candidate = seed.max(1);
        for _ in 0..=self.capacity {
            if !self
                .connections
                .iter()
                .any(|connection| connection.handle == candidate)
            {
                return Ok(candidate);
            }
            candidate = candidate
                .rotate_left(17)
                .wrapping_add(0x9e37_79b9_7f4a_7c15)
                .max(1);
        }
        Err(TcpConnectionError::Capacity)
    }

    pub fn keys(&self) -> Vec<(u64, u64)> {
        self.connections
            .iter()
            .map(|connection| (connection.handle, connection.owner))
            .collect()
    }

    pub fn abort_all(&mut self) {
        for connection in &mut self.connections {
            connection.abort();
        }
    }

    pub fn clear(&mut self) {
        self.connections.clear();
    }

    pub fn remove(&mut self, handle: u64, owner: u64) {
        self.connections
            .retain(|connection| connection.handle != handle || connection.owner != owner);
    }

    pub fn remove_closed(&mut self) {
        self.connections
            .retain(|connection| !matches!(connection.state, TcpState::Closed | TcpState::Reset));
    }

    pub fn len(&self) -> usize {
        self.connections.len()
    }

    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: [u8; 4] = [10, 0, 2, 15];
    const REMOTE: [u8; 4] = [10, 0, 2, 2];

    fn segment<'a>(
        flags: u16,
        sequence: u32,
        acknowledgment: u32,
        payload: &'a [u8],
    ) -> TcpSegment<'a> {
        TcpSegment {
            source_port: 80,
            destination_port: 50_000,
            sequence,
            acknowledgment,
            flags,
            window: 4096,
            urgent_pointer: 0,
            options: TcpOptions::default(),
            payload,
        }
    }

    fn connection(send_capacity: usize, receive_capacity: usize) -> TcpConnection {
        TcpConnection::connect(
            1,
            7,
            TcpTuple {
                local_address: LOCAL,
                local_port: 50_000,
                remote_address: REMOTE,
                remote_port: 80,
            },
            100,
            8,
            send_capacity,
            receive_capacity,
            100,
            2,
        )
    }

    fn establish(connection: &mut TcpConnection) {
        let syn = connection.poll_transmit(0).unwrap().unwrap();
        assert_eq!(syn.flags, TCP_FLAG_SYN);
        let syn_ack = TcpSegment {
            options: TcpOptions {
                maximum_segment_size: Some(4),
            },
            ..segment(TCP_FLAG_SYN | TCP_FLAG_ACK, 500, 101, &[])
        };
        assert_eq!(
            connection.on_segment(&syn_ack, 1),
            Ok(TcpReceiveResult::Acknowledge)
        );
        assert_eq!(connection.state, TcpState::Established);
        assert_eq!(connection.receive_next, 501);
    }

    #[test]
    fn header_checksum_payload_and_options() {
        for payload in [b"".as_slice(), b"odd".as_slice(), b"even".as_slice()] {
            let original = TcpSegment {
                options: TcpOptions {
                    maximum_segment_size: Some(1460),
                },
                payload,
                ..segment(TCP_FLAG_SYN, 1, 0, payload)
            };
            let mut bytes = [0u8; 64];
            let length = original.encode(REMOTE, LOCAL, &mut bytes).unwrap();
            assert_eq!(
                TcpSegment::decode(REMOTE, LOCAL, &bytes[..length]),
                Ok(original)
            );
            assert_eq!(
                TcpSegment::decode([11, 0, 2, 15], LOCAL, &bytes[..length]),
                Err(PacketError::InvalidChecksum)
            );
            bytes[4] ^= 1;
            assert_eq!(
                TcpSegment::decode(REMOTE, LOCAL, &bytes[..length]),
                Err(PacketError::InvalidChecksum)
            );
        }
    }

    #[test]
    fn invalid_offset_and_options_are_rejected() {
        let original = segment(TCP_FLAG_ACK, 1, 1, &[]);
        let mut bytes = [0u8; 32];
        let length = original.encode(REMOTE, LOCAL, &mut bytes).unwrap();
        bytes[12] = 4 << 4;
        assert_eq!(
            TcpSegment::decode(REMOTE, LOCAL, &bytes[..length]),
            Err(PacketError::InvalidHeader)
        );
        let options = [30, 8, 4, 0];
        assert_eq!(parse_options(&options), Err(PacketError::InvalidHeader));
        let skipped = [30, 4, 1, 2];
        assert_eq!(parse_options(&skipped), Ok(TcpOptions::default()));
        assert_eq!(
            TcpSegment {
                flags: TCP_FLAG_ACK | 0x40,
                ..original
            }
            .encode(REMOTE, LOCAL, &mut bytes),
            Err(PacketError::Unsupported)
        );
    }

    #[test]
    fn syn_ack_and_invalid_ack_transitions() {
        let mut invalid = connection(32, 32);
        invalid.poll_transmit(0).unwrap();
        assert_eq!(
            invalid.on_segment(&segment(TCP_FLAG_SYN | TCP_FLAG_ACK, 500, 99, &[]), 1),
            Err(TcpConnectionError::InvalidAcknowledgment)
        );
        let mut valid = connection(32, 32);
        establish(&mut valid);
    }

    #[test]
    fn send_segments_and_ack_releases_buffer() {
        let mut connection = connection(32, 32);
        establish(&mut connection);
        assert_eq!(
            connection.on_segment(&segment(TCP_FLAG_ACK, 501, 101, &[]), 2),
            Ok(TcpReceiveResult::DuplicateAck)
        );
        assert_eq!(
            connection.on_segment(&segment(TCP_FLAG_ACK, 501, 102, &[]), 2),
            Err(TcpConnectionError::InvalidAcknowledgment)
        );
        connection.queue_send(b"abcdefghij").unwrap();
        let first = connection.poll_transmit(2).unwrap().unwrap();
        assert_eq!(first.payload, b"abcd");
        assert!(connection.has_unacknowledged());
        assert_eq!(
            connection.on_segment(&segment(TCP_FLAG_ACK, 501, 105, &[]), 3),
            Ok(TcpReceiveResult::Accepted)
        );
        assert!(!connection.has_unacknowledged());
        let second = connection.poll_transmit(4).unwrap().unwrap();
        assert_eq!(second.payload, b"efgh");
    }

    #[test]
    fn duplicate_and_out_of_order_data_are_not_delivered() {
        let mut connection = connection(32, 8);
        establish(&mut connection);
        assert_eq!(
            connection.on_segment(&segment(TCP_FLAG_ACK, 501, 101, b"ab"), 2),
            Ok(TcpReceiveResult::Acknowledge)
        );
        assert_eq!(
            connection.on_segment(&segment(TCP_FLAG_ACK, 501, 101, b"ab"), 3),
            Ok(TcpReceiveResult::DuplicateSegment)
        );
        assert_eq!(
            connection.on_segment(&segment(TCP_FLAG_ACK, 510, 101, b"zz"), 4),
            Ok(TcpReceiveResult::OutOfOrder)
        );
        let mut received = [0; 8];
        assert_eq!(connection.receive(&mut received), 2);
        assert_eq!(&received[..2], b"ab");
    }

    #[test]
    fn receive_and_send_buffers_are_bounded() {
        let mut bounded = connection(2, 2);
        establish(&mut bounded);
        assert_eq!(
            bounded.queue_send(b"abc"),
            Err(TcpConnectionError::SendBufferFull)
        );
        assert_eq!(
            bounded.on_segment(&segment(TCP_FLAG_ACK, 501, 101, b"abc"), 2),
            Err(TcpConnectionError::ReceiveBufferFull)
        );

        let mut in_flight = connection(4, 4);
        establish(&mut in_flight);
        in_flight.queue_send(b"abcd").unwrap();
        in_flight.poll_transmit(2).unwrap();
        assert_eq!(
            in_flight.queue_send(b"x"),
            Err(TcpConnectionError::SendBufferFull)
        );
    }

    #[test]
    fn retransmission_and_retry_limit() {
        let mut connection = connection(8, 8);
        assert!(!connection.poll_transmit(0).unwrap().unwrap().retransmission);
        assert!(connection.poll_transmit(99).unwrap().is_none());
        assert!(
            connection
                .poll_transmit(100)
                .unwrap()
                .unwrap()
                .retransmission
        );
        assert!(connection.poll_transmit(299).unwrap().is_none());
        assert!(
            connection
                .poll_transmit(300)
                .unwrap()
                .unwrap()
                .retransmission
        );
        assert_eq!(
            connection.poll_transmit(700),
            Err(TcpConnectionError::RetryLimit)
        );
        assert_eq!(connection.state, TcpState::Reset);
    }

    #[test]
    fn active_and_passive_close_reach_terminal_states() {
        let mut active = connection(8, 8);
        establish(&mut active);
        active.request_close().unwrap();
        let fin = active.poll_transmit(2).unwrap().unwrap();
        assert_eq!(fin.flags, TCP_FLAG_FIN | TCP_FLAG_ACK);
        assert_eq!(active.state, TcpState::FinWait1);
        active
            .on_segment(&segment(TCP_FLAG_ACK, 501, active.send_next, &[]), 3)
            .unwrap();
        assert_eq!(active.state, TcpState::FinWait2);
        active
            .on_segment(
                &segment(TCP_FLAG_FIN | TCP_FLAG_ACK, 501, active.send_next, &[]),
                4,
            )
            .unwrap();
        assert_eq!(active.state, TcpState::TimeWait);
        active.tick(30_004);
        assert_eq!(active.state, TcpState::Closed);

        let mut passive = connection(8, 8);
        establish(&mut passive);
        passive
            .on_segment(&segment(TCP_FLAG_FIN | TCP_FLAG_ACK, 501, 101, &[]), 2)
            .unwrap();
        assert_eq!(passive.state, TcpState::CloseWait);
        passive.request_close().unwrap();
        passive.poll_transmit(3).unwrap();
        assert_eq!(passive.state, TcpState::LastAck);
        passive
            .on_segment(&segment(TCP_FLAG_ACK, 502, passive.send_next, &[]), 4)
            .unwrap();
        assert_eq!(passive.state, TcpState::Closed);
    }

    #[test]
    fn reset_is_terminal() {
        let mut connection = connection(8, 8);
        establish(&mut connection);
        assert_eq!(
            connection.on_segment(&segment(TCP_FLAG_RST, 501, 0, &[]), 2),
            Ok(TcpReceiveResult::Reset)
        );
        assert_eq!(connection.state, TcpState::Reset);
    }

    #[test]
    fn ephemeral_ports_owner_and_table_capacity() {
        let mut table = TcpConnectionTable::new(1);
        let first = connection(8, 8);
        table.insert(first).unwrap();
        assert_eq!(
            table.allocate_port(50_000 - TCP_EPHEMERAL_START),
            Ok(50_001)
        );
        assert!(matches!(
            table.get_mut(1, 8),
            Err(TcpConnectionError::Ownership)
        ));
        assert!(matches!(
            table.get_mut(2, 7),
            Err(TcpConnectionError::NotFound)
        ));
        assert_eq!(
            table.insert(connection(8, 8)),
            Err(TcpConnectionError::Capacity)
        );
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn sequence_wraparound_and_handle_collision_are_bounded() {
        assert!(sequence_before(u32::MAX, 0));
        assert!(sequence_after(0, u32::MAX));

        let mut wrapped = TcpConnection::connect(
            2,
            7,
            TcpTuple {
                local_address: LOCAL,
                local_port: 50_001,
                remote_address: REMOTE,
                remote_port: 80,
            },
            u32::MAX,
            8,
            8,
            8,
            100,
            2,
        );
        wrapped.poll_transmit(0).unwrap();
        assert_eq!(
            wrapped.on_segment(
                &TcpSegment {
                    options: TcpOptions {
                        maximum_segment_size: Some(4),
                    },
                    ..segment(TCP_FLAG_SYN | TCP_FLAG_ACK, u32::MAX, 0, &[])
                },
                1,
            ),
            Ok(TcpReceiveResult::Acknowledge)
        );
        wrapped.queue_send(b"wrap").unwrap();
        let sent = wrapped.poll_transmit(2).unwrap().unwrap();
        assert_eq!(sent.sequence, 0);
        assert_eq!(wrapped.send_next, 4);
        assert_eq!(
            wrapped.on_segment(&segment(TCP_FLAG_ACK, 0, 4, &[]), 3),
            Ok(TcpReceiveResult::Accepted)
        );

        let mut table = TcpConnectionTable::new(2);
        table.insert(connection(8, 8)).unwrap();
        let handle = table.allocate_handle(1).unwrap();
        assert_ne!(handle, 1);
        assert_ne!(handle, 0);
    }
}
