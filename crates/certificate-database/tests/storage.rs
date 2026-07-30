use std::collections::BTreeMap;

use mochios_certificate_database::storage::{
    REVOCATIONS_A_PATH, REVOCATIONS_B_PATH, STATE_PATH, SnapshotKind, SnapshotValidator,
    StorageBackend, StorageError, TRUST_A_PATH, TRUST_B_PATH, ValidatedSnapshot, load_database,
    persist_snapshot,
};
use mochios_certificate_database::{DatabaseState, Etag, STATE_LEN, Slot};

#[derive(Default)]
struct MemoryBackend {
    files: BTreeMap<String, Vec<u8>>,
    writes: Vec<String>,
    fail_path: Option<String>,
    corrupt_after_write: Option<String>,
}

impl MemoryBackend {
    fn insert(&mut self, path: &str, bytes: Vec<u8>) {
        self.files.insert(path.to_string(), bytes);
    }

    fn state(&self) -> DatabaseState {
        DatabaseState::decode(self.files.get(STATE_PATH).unwrap()).unwrap()
    }
}

impl StorageBackend for MemoryBackend {
    fn read(&mut self, path: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let mut bytes = self.files.get(path).cloned();
        if self.corrupt_after_write.as_deref() == Some(path)
            && self.writes.iter().any(|written| written == path)
            && let Some(bytes) = bytes.as_mut()
            && let Some(first) = bytes.first_mut()
        {
            *first ^= 0xff;
        }
        Ok(bytes)
    }

    fn write_sync(&mut self, path: &str, bytes: &[u8]) -> Result<(), StorageError> {
        if self.fail_path.as_deref() == Some(path) {
            return Err(StorageError::Backend);
        }
        self.writes.push(path.to_string());
        self.files.insert(path.to_string(), bytes.to_vec());
        Ok(())
    }
}

struct Validator;

impl SnapshotValidator for Validator {
    fn validate(
        &mut self,
        _kind: SnapshotKind,
        bytes: &[u8],
    ) -> Result<ValidatedSnapshot, StorageError> {
        if bytes.len() != 24 {
            return Err(StorageError::InvalidSnapshot);
        }
        Ok(ValidatedSnapshot {
            snapshot_version: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            generated_at: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            expires_at: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        })
    }
}

fn snapshot(version: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(24);
    bytes.extend_from_slice(&version.to_le_bytes());
    bytes.extend_from_slice(&(version * 10).to_le_bytes());
    bytes.extend_from_slice(&(version * 10 + 100).to_le_bytes());
    bytes
}

fn etag(version: u64) -> Etag {
    Etag::parse(&format!("\"v{version}\"")).unwrap()
}

#[test]
fn updates_alternate_from_a_to_b_and_back_to_a() {
    let mut backend = MemoryBackend::default();
    let mut validator = Validator;
    let mut state = DatabaseState::default();

    assert_eq!(
        persist_snapshot(
            &mut backend,
            &mut validator,
            &mut state,
            SnapshotKind::Trust,
            &snapshot(1),
            etag(1),
            101,
        ),
        Ok(Slot::B)
    );
    assert_eq!(state.active_trust_slot, Slot::B);
    assert_eq!(backend.files.get(TRUST_B_PATH), Some(&snapshot(1)));
    assert_eq!(backend.state(), state);

    assert_eq!(
        persist_snapshot(
            &mut backend,
            &mut validator,
            &mut state,
            SnapshotKind::Trust,
            &snapshot(2),
            etag(2),
            202,
        ),
        Ok(Slot::A)
    );
    assert_eq!(state.active_trust_slot, Slot::A);
    assert_eq!(backend.files.get(TRUST_A_PATH), Some(&snapshot(2)));
    assert_eq!(backend.state(), state);
}

#[test]
fn snapshot_is_synced_and_read_back_before_state_is_committed() {
    let mut backend = MemoryBackend {
        corrupt_after_write: Some(TRUST_B_PATH.to_string()),
        ..MemoryBackend::default()
    };
    let mut validator = Validator;
    let mut state = DatabaseState::default();

    assert_eq!(
        persist_snapshot(
            &mut backend,
            &mut validator,
            &mut state,
            SnapshotKind::Trust,
            &snapshot(1),
            etag(1),
            1,
        ),
        Err(StorageError::WriteBackMismatch)
    );
    assert!(!backend.files.contains_key(STATE_PATH));
    assert_eq!(state, DatabaseState::default());
}

#[test]
fn state_write_failure_leaves_previous_active_slot_selected() {
    let mut backend = MemoryBackend::default();
    let mut validator = Validator;
    let mut state = DatabaseState::default();
    persist_snapshot(
        &mut backend,
        &mut validator,
        &mut state,
        SnapshotKind::Trust,
        &snapshot(1),
        etag(1),
        1,
    )
    .unwrap();
    let committed = state.clone();
    backend.fail_path = Some(STATE_PATH.to_string());

    assert_eq!(
        persist_snapshot(
            &mut backend,
            &mut validator,
            &mut state,
            SnapshotKind::Trust,
            &snapshot(2),
            etag(2),
            2,
        ),
        Err(StorageError::Backend)
    );
    assert_eq!(state, committed);
    assert_eq!(backend.state(), committed);
    assert_eq!(backend.files.get(TRUST_A_PATH), Some(&snapshot(2)));
}

#[test]
fn corrupt_active_slot_falls_back_and_repairs_state() {
    let mut backend = MemoryBackend::default();
    backend.insert(TRUST_A_PATH, snapshot(1));
    backend.insert(TRUST_B_PATH, vec![0xff]);
    let mut state = DatabaseState {
        generation: 8,
        active_trust_slot: Slot::B,
        ..DatabaseState::default()
    };
    state.trust.snapshot_version = 2;
    let mut encoded = [0; STATE_LEN];
    state.encode(&mut encoded).unwrap();
    backend.insert(STATE_PATH, encoded.to_vec());

    let loaded = load_database(&mut backend, &mut Validator).unwrap();
    assert!(loaded.recovered);
    assert_eq!(loaded.state.active_trust_slot, Slot::A);
    assert_eq!(loaded.state.trust.snapshot_version, 1);
    assert_eq!(loaded.trust, Some(snapshot(1)));
    assert_eq!(backend.state(), loaded.state);
}

#[test]
fn corrupt_state_chooses_newest_valid_slots() {
    let mut backend = MemoryBackend::default();
    backend.insert(STATE_PATH, vec![0; STATE_LEN]);
    backend.insert(TRUST_A_PATH, snapshot(1));
    backend.insert(TRUST_B_PATH, snapshot(3));
    backend.insert(REVOCATIONS_A_PATH, snapshot(4));
    backend.insert(REVOCATIONS_B_PATH, snapshot(2));

    let loaded = load_database(&mut backend, &mut Validator).unwrap();
    assert!(loaded.recovered);
    assert_eq!(loaded.state.active_trust_slot, Slot::B);
    assert_eq!(loaded.state.trust.snapshot_version, 3);
    assert_eq!(loaded.state.active_revocation_slot, Slot::A);
    assert_eq!(loaded.state.revocations.snapshot_version, 4);
    assert_eq!(loaded.state.trust.etag, Etag::none());
    assert_eq!(loaded.state.revocations.etag, Etag::none());
}

#[test]
fn both_corrupt_slots_fall_back_to_empty_database() {
    let mut backend = MemoryBackend::default();
    backend.insert(TRUST_A_PATH, vec![1]);
    backend.insert(TRUST_B_PATH, vec![2]);
    backend.insert(REVOCATIONS_A_PATH, vec![3]);
    backend.insert(REVOCATIONS_B_PATH, vec![4]);

    let loaded = load_database(&mut backend, &mut Validator).unwrap();
    assert!(loaded.recovered);
    assert!(loaded.trust.is_none());
    assert!(loaded.revocations.is_none());
    assert_eq!(loaded.state.trust.snapshot_version, 0);
    assert_eq!(loaded.state.revocations.snapshot_version, 0);
}

#[test]
fn rollback_and_snapshot_sync_failure_do_not_change_state() {
    let mut backend = MemoryBackend::default();
    let mut validator = Validator;
    let mut state = DatabaseState::default();
    persist_snapshot(
        &mut backend,
        &mut validator,
        &mut state,
        SnapshotKind::Revocations,
        &snapshot(2),
        etag(2),
        2,
    )
    .unwrap();
    let committed = state.clone();
    assert_eq!(
        persist_snapshot(
            &mut backend,
            &mut validator,
            &mut state,
            SnapshotKind::Revocations,
            &snapshot(1),
            etag(1),
            3,
        ),
        Err(StorageError::SnapshotRollback)
    );
    backend.fail_path = Some(REVOCATIONS_A_PATH.to_string());
    assert_eq!(
        persist_snapshot(
            &mut backend,
            &mut validator,
            &mut state,
            SnapshotKind::Revocations,
            &snapshot(3),
            etag(3),
            4,
        ),
        Err(StorageError::Backend)
    );
    assert_eq!(state, committed);
}
