use mochios_certificate_database::{
    DatabaseState, DecodeError, Etag, EtagError, FORMAT_VERSION, MAGIC, MAX_ETAG_BYTES, STATE_LEN,
    Slot, SnapshotMetadata,
};

fn state() -> DatabaseState {
    DatabaseState {
        generation: 7,
        active_trust_slot: Slot::B,
        active_revocation_slot: Slot::A,
        trust: SnapshotMetadata {
            snapshot_version: 11,
            generated_at: 12,
            expires_at: 13,
            last_checked_at: 14,
            etag: Etag::parse("\"trust-v11\"").unwrap(),
        },
        revocations: SnapshotMetadata {
            snapshot_version: 21,
            generated_at: 22,
            expires_at: 23,
            last_checked_at: 24,
            etag: Etag::parse("W/\"revocations-v21\"").unwrap(),
        },
    }
}

#[test]
fn state_round_trip_and_fixed_layout() {
    let state = state();
    let mut bytes = [0; STATE_LEN];
    assert_eq!(state.encode(&mut bytes), Ok(STATE_LEN));
    assert_eq!(&bytes[..4], &MAGIC.to_le_bytes());
    assert_eq!(&bytes[4..6], &FORMAT_VERSION.to_le_bytes());
    assert_eq!(&bytes[6..8], &(STATE_LEN as u16).to_le_bytes());
    assert_eq!(&bytes[8..16], &7u64.to_le_bytes());
    assert_eq!(&bytes[16..18], &[1, 0]);
    assert_eq!(&bytes[24..32], &11u64.to_le_bytes());
    assert_eq!(&bytes[56..58], &11u16.to_le_bytes());
    assert_eq!(&bytes[64..72], &21u64.to_le_bytes());
    assert_eq!(&bytes[96..98], &19u16.to_le_bytes());
    assert_eq!(&bytes[104..115], b"\"trust-v11\"");
    assert_eq!(&bytes[232..251], b"W/\"revocations-v21\"");
    assert_eq!(DatabaseState::decode(&bytes), Ok(state));
}

#[test]
fn slots_toggle_without_implicit_state_changes() {
    assert_eq!(Slot::A.inactive(), Slot::B);
    assert_eq!(Slot::B.inactive(), Slot::A);
    let empty = DatabaseState::default();
    assert_eq!(empty.generation, 0);
    assert_eq!(empty.active_trust_slot, Slot::A);
    assert_eq!(empty.active_revocation_slot, Slot::A);
    assert!(empty.trust.etag.is_none());
    assert!(empty.revocations.etag.is_none());
}

#[test]
fn malformed_header_length_slot_reserved_and_checksum_are_rejected() {
    let mut bytes = [0; STATE_LEN];
    state().encode(&mut bytes).unwrap();

    assert!(matches!(
        DatabaseState::decode(&bytes[..STATE_LEN - 1]),
        Err(DecodeError::InvalidLength { .. })
    ));
    let mut excess = [0; STATE_LEN + 1];
    excess[..STATE_LEN].copy_from_slice(&bytes);
    assert!(matches!(
        DatabaseState::decode(&excess),
        Err(DecodeError::InvalidLength { .. })
    ));

    for (offset, value, expected) in [
        (0, 0, "magic"),
        (4, 2, "version"),
        (6, 0, "length"),
        (16, 2, "slot"),
        (18, 1, "reserved"),
    ] {
        let mut malformed = bytes;
        malformed[offset] = value;
        let error = DatabaseState::decode(&malformed).unwrap_err();
        match expected {
            "magic" => assert!(matches!(error, DecodeError::InvalidMagic(_))),
            "version" => assert!(matches!(error, DecodeError::UnsupportedVersion(2))),
            "length" => assert!(matches!(error, DecodeError::InvalidEncodedLength(_))),
            "slot" => assert_eq!(error, DecodeError::InvalidSlot(2)),
            "reserved" => assert_eq!(error, DecodeError::NonZeroReserved),
            _ => unreachable!(),
        }
    }

    bytes[24] ^= 1;
    assert_eq!(
        DatabaseState::decode(&bytes),
        Err(DecodeError::ChecksumMismatch)
    );
}

#[test]
fn etags_accept_strong_and_weak_forms_and_enforce_bounds() {
    assert_eq!(Etag::parse("\"strong\"").unwrap().as_str(), "\"strong\"");
    assert_eq!(Etag::parse("W/\"weak\"").unwrap().as_str(), "W/\"weak\"");
    assert_eq!(Etag::parse(""), Ok(Etag::none()));
    assert_eq!(Etag::parse("unquoted"), Err(EtagError::Invalid));
    assert_eq!(Etag::parse("\"bad value\""), Err(EtagError::Invalid));
    let oversized = "x".repeat(MAX_ETAG_BYTES + 1);
    assert_eq!(Etag::parse(&oversized), Err(EtagError::TooLong));
}

#[test]
fn output_buffer_must_hold_the_complete_fixed_record() {
    let mut short = [0; STATE_LEN - 1];
    assert!(matches!(
        state().encode(&mut short),
        Err(mochios_certificate_database::EncodeError::BufferTooSmall { .. })
    ));
}
