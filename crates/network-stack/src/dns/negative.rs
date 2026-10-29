//! RFC 2308 negative answers. Only an authority-section SOA covering the
//! terminal name supplies a cache lifetime; absence alone supplies none.
use super::{DnsError, DnsRecordName, DnsResponseCode, decode_record_name, normalize_ttl};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsNegativeKind {
    NameError,
    NoData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsSoa {
    pub owner: DnsRecordName,
    pub primary: DnsRecordName,
    pub mailbox: DnsRecordName,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    pub(super) ttl: u32,
}
impl DnsSoa {
    /// The negative TTL, already bounded by SOA.MINIMUM. Cached copies are
    /// aged from the original receipt; they cannot restart this lifetime.
    pub fn ttl_seconds(&self) -> u32 {
        self.ttl
    }

    pub(super) fn decode(
        packet: &[u8],
        owner: DnsRecordName,
        ttl: u32,
        start: usize,
        end: usize,
    ) -> Result<Self, DnsError> {
        let (primary, next) = decode_record_name(packet, start, end)?;
        let (mailbox, next) = decode_record_name(packet, next, end)?;
        if next.checked_add(20) != Some(end) {
            return Err(DnsError::InvalidRecordLength);
        }
        let read = |offset| super::super::read_u32(packet, next + offset);
        let minimum = read(16)?;
        Ok(Self {
            owner,
            primary,
            mailbox,
            serial: read(0)?,
            refresh: read(4)?,
            retry: read(8)?,
            expire: read(12)?,
            minimum,
            ttl: ttl.min(normalize_ttl(minimum)),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsNegative {
    pub kind: DnsNegativeKind,
    pub soa: Option<DnsSoa>,
}
impl DnsNegative {
    pub fn error(&self) -> DnsError {
        match self.kind {
            DnsNegativeKind::NameError => DnsError::Response(DnsResponseCode::NameError),
            DnsNegativeKind::NoData => DnsError::NoData,
        }
    }
}

/// Match complete labels, including binary labels and the root. A textual
/// suffix (e.g. badexample.test vs example.test) is not zone containment.
pub(super) fn covers(zone: &DnsRecordName, name: &DnsRecordName) -> bool {
    let mut offset = 0;
    loop {
        if &name.wire()[offset..] == zone.wire() {
            return true;
        }
        let length = usize::from(name.wire()[offset]);
        if length == 0 {
            return false;
        }
        offset += 1 + length;
    }
}

pub(super) fn closest(soas: &[DnsSoa], name: &DnsRecordName) -> Result<Option<DnsSoa>, DnsError> {
    let Some(mut found) = soas
        .iter()
        .filter(|soa| covers(&soa.owner, name))
        .max_by_key(|soa| soa.owner.wire().len())
        .cloned()
    else {
        return Ok(None);
    };
    for soa in soas.iter().filter(|soa| soa.owner == found.owner) {
        let ttl = found.ttl.min(soa.ttl);
        found.ttl = soa.ttl;
        if &found != soa {
            return Err(DnsError::InvalidHeader);
        }
        found.ttl = ttl;
    }
    Ok(Some(found))
}
