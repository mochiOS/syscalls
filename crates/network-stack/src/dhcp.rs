use crate::PacketError;
pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_FIXED_LEN: usize = 240;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpState {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Ack = 5,
    Nak = 6,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhcpOffer {
    pub address: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub gateway: [u8; 4],
    pub dns: [u8; 4],
    pub lease_seconds: u32,
    pub server: [u8; 4],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhcpMessage {
    pub message_type: DhcpMessageType,
    pub offer: DhcpOffer,
}
pub fn encode_request(
    kind: DhcpMessageType,
    xid: u32,
    mac: [u8; 6],
    requested: Option<[u8; 4]>,
    server: Option<[u8; 4]>,
    out: &mut [u8],
) -> Result<usize, PacketError> {
    if kind != DhcpMessageType::Discover && kind != DhcpMessageType::Request {
        return Err(PacketError::Unsupported);
    }
    if out.len() < 300 {
        return Err(PacketError::Truncated);
    }
    out[..300].fill(0);
    out[0] = 1;
    out[1] = 1;
    out[2] = 6;
    out[4..8].copy_from_slice(&xid.to_be_bytes());
    out[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
    out[28..34].copy_from_slice(&mac);
    out[236..240].copy_from_slice(&[99, 130, 83, 99]);
    let mut i = 240;
    out[i..i + 3].copy_from_slice(&[53, 1, kind as u8]);
    i += 3;
    if let Some(ip) = requested {
        out[i] = 50;
        out[i + 1] = 4;
        out[i + 2..i + 6].copy_from_slice(&ip);
        i += 6
    }
    if let Some(ip) = server {
        out[i] = 54;
        out[i + 1] = 4;
        out[i + 2..i + 6].copy_from_slice(&ip);
        i += 6
    }
    out[i..i + 8].copy_from_slice(&[55, 6, 1, 3, 6, 51, 54, 58]);
    i += 8;
    out[i] = 255;
    Ok(i + 1)
}
pub fn decode_reply(b: &[u8], xid: u32, mac: [u8; 6]) -> Result<DhcpMessage, PacketError> {
    if b.len() < DHCP_FIXED_LEN {
        return Err(PacketError::Truncated);
    }
    if b[0] != 2 || b[1] != 1 || b[2] != 6 {
        return Err(PacketError::InvalidHeader);
    }
    if u32::from_be_bytes([b[4], b[5], b[6], b[7]]) != xid || b[28..34] != mac {
        return Err(PacketError::Mismatch);
    }
    if b[236..240] != [99, 130, 83, 99] {
        return Err(PacketError::InvalidHeader);
    }
    let address = [b[16], b[17], b[18], b[19]];
    let mut ty = None;
    let mut mask = [0; 4];
    let mut gateway = [0; 4];
    let mut dns = [0; 4];
    let mut lease = 0;
    let mut server = [0; 4];
    let mut i = 240;
    let mut count = 0;
    while i < b.len() && count < 128 {
        count += 1;
        let code = b[i];
        i += 1;
        if code == 255 {
            break;
        }
        if code == 0 {
            continue;
        }
        let Some(&len) = b.get(i) else {
            return Err(PacketError::InvalidLength);
        };
        i += 1;
        let end = i
            .checked_add(len as usize)
            .ok_or(PacketError::InvalidLength)?;
        let value = b.get(i..end).ok_or(PacketError::InvalidLength)?;
        match (code, len) {
            (53, 1) => {
                ty = Some(match value[0] {
                    2 => DhcpMessageType::Offer,
                    5 => DhcpMessageType::Ack,
                    6 => DhcpMessageType::Nak,
                    _ => return Err(PacketError::Unsupported),
                })
            }
            (1, 4) => mask.copy_from_slice(value),
            (3, l) if l >= 4 => gateway.copy_from_slice(&value[..4]),
            (6, l) if l >= 4 => dns.copy_from_slice(&value[..4]),
            (51, 4) => {
                lease =
                    u32::from_be_bytes(value.try_into().map_err(|_| PacketError::InvalidLength)?)
            }
            (54, 4) => server.copy_from_slice(value),
            _ => {}
        }
        i = end
    }
    let message_type = ty.ok_or(PacketError::InvalidHeader)?;
    if server == [0; 4] || address == [0; 4] {
        return Err(PacketError::InvalidHeader);
    }
    Ok(DhcpMessage {
        message_type,
        offer: DhcpOffer {
            address,
            subnet_mask: mask,
            gateway,
            dns,
            lease_seconds: lease,
            server,
        },
    })
}
pub struct DhcpClient {
    pub state: DhcpState,
    pub xid: u32,
    pub mac: [u8; 6],
    pub offer: Option<DhcpOffer>,
    pub retries: u8,
    pub next_retry: u64,
    pub lease_deadline: u64,
}
impl DhcpClient {
    pub const fn new(xid: u32, mac: [u8; 6]) -> Self {
        Self {
            state: DhcpState::Init,
            xid,
            mac,
            offer: None,
            retries: 0,
            next_retry: 0,
            lease_deadline: 0,
        }
    }
    pub fn begin(&mut self, now: u64) {
        self.state = DhcpState::Selecting;
        self.retries = 0;
        self.next_retry = now.saturating_add(1000)
    }
    pub fn accept(&mut self, msg: DhcpMessage, now: u64) -> Result<(), PacketError> {
        match (self.state, msg.message_type) {
            (DhcpState::Selecting, DhcpMessageType::Offer) => {
                self.offer = Some(msg.offer);
                self.state = DhcpState::Requesting;
                self.next_retry = now.saturating_add(1000);
                Ok(())
            }
            (DhcpState::Requesting, DhcpMessageType::Ack)
                if self.offer.is_some_and(|offer| {
                    offer.address == msg.offer.address && offer.server == msg.offer.server
                }) =>
            {
                self.state = DhcpState::Bound;
                self.lease_deadline =
                    now.saturating_add(u64::from(msg.offer.lease_seconds).saturating_mul(1000));
                Ok(())
            }
            (_, DhcpMessageType::Nak) => {
                self.state = DhcpState::Failed;
                Ok(())
            }
            _ => Err(PacketError::Mismatch),
        }
    }
    pub fn tick(&mut self, now: u64) {
        if self.state == DhcpState::Bound
            && self.lease_deadline.saturating_sub(now) <= self.lease_deadline / 2
        {
            self.state = DhcpState::Renewing;
            self.next_retry = now
        }
        if matches!(
            self.state,
            DhcpState::Selecting
                | DhcpState::Requesting
                | DhcpState::Renewing
                | DhcpState::Rebinding
        ) && now >= self.next_retry
        {
            self.retries = self.retries.saturating_add(1);
            self.next_retry = now.saturating_add(1000u64 << self.retries.min(5));
            if self.retries >= 8 {
                self.state = DhcpState::Failed
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn offer() -> [u8; 260] {
        let mut b = [0; 260];
        b[0] = 2;
        b[1] = 1;
        b[2] = 6;
        b[4..8].copy_from_slice(&7u32.to_be_bytes());
        b[16..20].copy_from_slice(&[10, 0, 2, 15]);
        b[28..34].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        b[236..240].copy_from_slice(&[99, 130, 83, 99]);
        b[240..260].copy_from_slice(&[
            53, 1, 2, 1, 4, 255, 255, 255, 0, 3, 4, 10, 0, 2, 2, 54, 4, 10, 0, 2,
        ]);
        b
    }
    #[test]
    fn options_and_xid() {
        let mut b = offer();
        let mut v = b.to_vec();
        v.push(2);
        v.push(51);
        v.push(4);
        v.extend_from_slice(&3600u32.to_be_bytes());
        v.push(255);
        let m = decode_reply(&v, 7, [1, 2, 3, 4, 5, 6]).unwrap();
        assert_eq!(m.offer.address, [10, 0, 2, 15]);
        assert_eq!(
            decode_reply(&v, 8, [1, 2, 3, 4, 5, 6]),
            Err(PacketError::Mismatch)
        );
        b[259] = 99;
        assert!(decode_reply(&b, 7, [1, 2, 3, 4, 5, 6]).is_err())
    }
    #[test]
    fn malformed_option() {
        let mut b = offer().to_vec();
        b.push(1);
        b.push(20);
        assert_eq!(
            decode_reply(&b, 7, [1, 2, 3, 4, 5, 6]),
            Err(PacketError::InvalidLength)
        )
    }
}
