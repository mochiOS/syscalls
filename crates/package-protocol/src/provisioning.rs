//! Device-wide first-login installation of the fixed mochiOS application set.
//! These messages request policy decisions; none is an authorization by itself.
use super::ProtocolError;

/// Broker endpoint opcode. The request must come from the measured built-in Store.
pub const OPCODE: u32 = u32::from_le_bytes(*b"MPS1");
/// Publisher identity of the official mochiOS application certificate.
pub const PUBLISHER: &str = "019f9e5ac6687902b0e72fe53abfbef1";
/// Fixed installation order. Adding applications is an OS policy change.
pub const APPLICATIONS: [(&str, &str); 5] = [
    ("org.mochios.terra", "Terra"),
    ("org.mochios.edit", "Edit"),
    ("org.mochios.calendar", "Calendar"),
    ("org.mochios.mail", "Mail"),
    ("org.mochios.calculator", "Calculator"),
];
/// Maximum length of one local, human-readable failure reason.
pub const MAX_ERROR: usize = 256;
/// Upper bound for a complete five-application snapshot.
pub const MAX_SNAPSHOT: usize = 16 + APPLICATIONS.len() * (12 + MAX_ERROR);

/// Durable installation state. Only the broker may establish `Complete`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    /// Not installed yet, including interrupted attempts.
    Pending = 0,
    /// Retrieving a compatible release or its package bytes.
    Downloading = 1,
    /// Verified bytes are being committed through package.service.
    Installing = 2,
    /// Retryable failure; the error is available in AppStore.
    Failed = 3,
    /// Already satisfied, or explicitly removed after installation.
    Complete = 4,
}

impl Phase {
    fn decode(value: u8) -> Result<Self, ProtocolError> {
        match value {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Downloading),
            2 => Ok(Self::Installing),
            3 => Ok(Self::Failed),
            4 => Ok(Self::Complete),
            _ => Err(ProtocolError::InvalidField),
        }
    }
}

/// Borrowed progress record; error strings never contain control characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress<'a> {
    /// Current installation phase.
    pub phase: Phase,
    /// Download percentage, in the inclusive range 0 through 100.
    pub percent: u8,
    /// Number of started attempts, maintained by the broker.
    pub attempts: u32,
    /// Most recent failure, kept locally and never sent to the catalog.
    pub error: &'a str,
}

impl Default for Progress<'_> {
    fn default() -> Self {
        Self {
            phase: Phase::Pending,
            percent: 0,
            attempts: 0,
            error: "",
        }
    }
}

/// A query is read-only except for reconciliation with installed package records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    /// Read device progress without acquiring the background worker lease.
    Query,
    /// Acquire or renew the one measured worker lease.
    Claim,
    /// Publish progress for one application; this cannot mark it complete.
    Progress {
        index: usize,
        phase: Phase,
        percent: u8,
        error: &'a str,
    },
    /// Relinquish the current worker lease.
    Release,
    /// Request a single-use grant for one attached prepared package object.
    Authorize,
}

/// Encode a versioned broker request. No file paths or caller identity are sent.
pub fn encode_request(request: Request<'_>, output: &mut [u8]) -> Result<usize, ProtocolError> {
    let (command, index, phase, percent, error) = match request {
        Request::Query => (0, 0, Phase::Pending, 0, ""),
        Request::Claim => (1, 0, Phase::Pending, 0, ""),
        Request::Release => (3, 0, Phase::Pending, 0, ""),
        Request::Authorize => (4, 0, Phase::Pending, 0, ""),
        Request::Progress {
            index,
            phase,
            percent,
            error,
        } => {
            if index >= APPLICATIONS.len() || phase == Phase::Complete {
                return Err(ProtocolError::InvalidField);
            }
            validate(percent, error)?;
            (2, index as u8, phase, percent, error)
        }
    };
    let length = 16 + error.len();
    let output = output
        .get_mut(..length)
        .ok_or(ProtocolError::BufferTooSmall)?;
    output.fill(0);
    output[..4].copy_from_slice(&OPCODE.to_le_bytes());
    output[4..6].copy_from_slice(&1u16.to_le_bytes());
    output[6] = command;
    output[8] = index;
    output[9] = phase as u8;
    output[10] = percent;
    output[12..14].copy_from_slice(&(error.len() as u16).to_le_bytes());
    output[16..].copy_from_slice(error.as_bytes());
    Ok(length)
}

/// Decode strictly: reserved fields, lengths, phases and UTF-8 must be canonical.
pub fn decode_request(bytes: &[u8]) -> Result<Request<'_>, ProtocolError> {
    if bytes.len() < 16
        || bytes[..4] != OPCODE.to_le_bytes()
        || bytes[4..6] != 1u16.to_le_bytes()
        || bytes[7] != 0
        || bytes[11] != 0
        || bytes[14..16] != [0; 2]
    {
        return Err(ProtocolError::InvalidField);
    }
    let length = u16::from_le_bytes(bytes[12..14].try_into().unwrap()) as usize;
    if bytes.len() != 16 + length {
        return Err(ProtocolError::InvalidLength);
    }
    if bytes[6] != 2 {
        if bytes[8..14] != [0; 6] || length != 0 {
            return Err(ProtocolError::InvalidField);
        }
        return match bytes[6] {
            0 => Ok(Request::Query),
            1 => Ok(Request::Claim),
            3 => Ok(Request::Release),
            4 => Ok(Request::Authorize),
            _ => Err(ProtocolError::UnexpectedOpcode),
        };
    }
    let error = core::str::from_utf8(&bytes[16..]).map_err(|_| ProtocolError::InvalidField)?;
    let phase = Phase::decode(bytes[9])?;
    validate(bytes[10], error)?;
    if bytes[8] as usize >= APPLICATIONS.len() || phase == Phase::Complete {
        return Err(ProtocolError::InvalidField);
    }
    Ok(Request::Progress {
        index: bytes[8] as usize,
        phase,
        percent: bytes[10],
        error,
    })
}

fn validate(percent: u8, error: &str) -> Result<(), ProtocolError> {
    if percent > 100 || error.len() > MAX_ERROR || error.chars().any(char::is_control) {
        Err(ProtocolError::InvalidField)
    } else {
        Ok(())
    }
}

/// Encode a fixed-order device snapshot, also used inside the durable ledger.
pub fn encode_snapshot(
    rows: &[Progress<'_>; 5],
    output: &mut [u8],
) -> Result<usize, ProtocolError> {
    let length = 16 + rows.iter().map(|r| 12 + r.error.len()).sum::<usize>();
    let output = output
        .get_mut(..length)
        .ok_or(ProtocolError::BufferTooSmall)?;
    output.fill(0);
    output[..8].copy_from_slice(b"MPSSTATE");
    output[8..12].copy_from_slice(&1u32.to_le_bytes());
    output[12..16].copy_from_slice(&5u32.to_le_bytes());
    let mut cursor = 16;
    for row in rows {
        validate(row.percent, row.error)?;
        output[cursor] = row.phase as u8;
        output[cursor + 1] = row.percent;
        output[cursor + 4..cursor + 8].copy_from_slice(&row.attempts.to_le_bytes());
        output[cursor + 8..cursor + 10].copy_from_slice(&(row.error.len() as u16).to_le_bytes());
        output[cursor + 12..cursor + 12 + row.error.len()].copy_from_slice(row.error.as_bytes());
        cursor += 12 + row.error.len();
    }
    Ok(length)
}

/// Decode a complete bounded snapshot. Unknown versions and trailing bytes fail.
pub fn decode_snapshot(bytes: &[u8]) -> Result<[Progress<'_>; 5], ProtocolError> {
    if bytes.len() < 16
        || bytes.len() > MAX_SNAPSHOT
        || &bytes[..8] != b"MPSSTATE"
        || bytes[8..12] != 1u32.to_le_bytes()
        || bytes[12..16] != 5u32.to_le_bytes()
    {
        return Err(ProtocolError::InvalidField);
    }
    let mut rows = [Progress::default(); 5];
    let mut cursor = 16;
    for row in &mut rows {
        let record = bytes
            .get(cursor..cursor + 12)
            .ok_or(ProtocolError::InvalidLength)?;
        if record[2..4] != [0; 2] || record[10..12] != [0; 2] {
            return Err(ProtocolError::InvalidField);
        }
        let length = u16::from_le_bytes(record[8..10].try_into().unwrap()) as usize;
        cursor += 12;
        let error = core::str::from_utf8(
            bytes
                .get(cursor..cursor + length)
                .ok_or(ProtocolError::InvalidLength)?,
        )
        .map_err(|_| ProtocolError::InvalidField)?;
        validate(record[1], error)?;
        *row = Progress {
            phase: Phase::decode(record[0])?,
            percent: record[1],
            attempts: u32::from_le_bytes(record[4..8].try_into().unwrap()),
            error,
        };
        cursor += length;
    }
    if cursor != bytes.len() {
        return Err(ProtocolError::InvalidLength);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_bounded_and_cannot_report_completion() {
        let mut bytes = [0; 512];
        for request in [
            Request::Query,
            Request::Claim,
            Request::Release,
            Request::Authorize,
            Request::Progress {
                index: 4,
                phase: Phase::Failed,
                percent: 42,
                error: "Offline",
            },
        ] {
            let n = encode_request(request, &mut bytes).unwrap();
            assert_eq!(decode_request(&bytes[..n]), Ok(request));
            assert!(decode_request(&bytes[..n - 1]).is_err());
        }
        for (index, phase, percent, error) in [
            (5, Phase::Pending, 0, ""),
            (0, Phase::Complete, 100, ""),
            (0, Phase::Pending, 101, ""),
            (0, Phase::Failed, 0, "bad\ntext"),
        ] {
            assert!(
                encode_request(
                    Request::Progress {
                        index,
                        phase,
                        percent,
                        error
                    },
                    &mut bytes
                )
                .is_err()
            );
        }
    }

    #[test]
    fn snapshots_roundtrip_and_reject_truncation_reserved_bytes_and_versions() {
        let mut rows = [Progress::default(); 5];
        rows[1] = Progress {
            phase: Phase::Failed,
            percent: 15,
            attempts: 3,
            error: "No compatible release",
        };
        let mut bytes = [0; MAX_SNAPSHOT];
        let n = encode_snapshot(&rows, &mut bytes).unwrap();
        assert_eq!(decode_snapshot(&bytes[..n]).unwrap(), rows);
        for length in 0..n {
            assert!(decode_snapshot(&bytes[..length]).is_err());
        }
        bytes[18] = 1;
        assert!(decode_snapshot(&bytes[..n]).is_err());
        bytes[18] = 0;
        bytes[8] = 2;
        assert!(decode_snapshot(&bytes[..n]).is_err());
    }
}
