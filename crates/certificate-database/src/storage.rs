use crate::{DatabaseState, Etag, STATE_LEN, Slot, SnapshotMetadata};
use alloc::vec::Vec;

pub const DATABASE_DIRECTORY: &str = "/libraries/certificate";
pub const STATE_PATH: &str = "/libraries/certificate/state.bin";
pub const TRUST_A_PATH: &str = "/libraries/certificate/trust-a.json";
pub const TRUST_B_PATH: &str = "/libraries/certificate/trust-b.json";
pub const REVOCATIONS_A_PATH: &str = "/libraries/certificate/revocations-a.json";
pub const REVOCATIONS_B_PATH: &str = "/libraries/certificate/revocations-b.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotKind {
    Trust,
    Revocations,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedSnapshot {
    pub snapshot_version: u64,
    pub generated_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageError {
    Backend,
    InvalidSnapshot,
    SnapshotRollback,
    WriteBackMismatch,
    StateEncoding,
    GenerationOverflow,
}

pub trait StorageBackend {
    fn read(&mut self, path: &str) -> Result<Option<Vec<u8>>, StorageError>;
    fn write_sync(&mut self, path: &str, bytes: &[u8]) -> Result<(), StorageError>;
}

pub trait SnapshotValidator {
    fn validate(
        &mut self,
        kind: SnapshotKind,
        bytes: &[u8],
    ) -> Result<ValidatedSnapshot, StorageError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedDatabase {
    pub state: DatabaseState,
    pub trust: Option<Vec<u8>>,
    pub revocations: Option<Vec<u8>>,
    pub recovered: bool,
}

pub fn load_database<B: StorageBackend, V: SnapshotValidator>(
    backend: &mut B,
    validator: &mut V,
) -> Result<LoadedDatabase, StorageError> {
    let stored_state = backend
        .read(STATE_PATH)?
        .and_then(|bytes| DatabaseState::decode(&bytes).ok());
    let mut state = stored_state.clone().unwrap_or_default();

    let trust = load_kind(
        backend,
        validator,
        SnapshotKind::Trust,
        stored_state.as_ref(),
    )?;
    let revocations = load_kind(
        backend,
        validator,
        SnapshotKind::Revocations,
        stored_state.as_ref(),
    )?;

    let mut recovered = stored_state.is_none();
    recovered |= apply_loaded(&mut state, SnapshotKind::Trust, trust.as_ref());
    recovered |= apply_loaded(&mut state, SnapshotKind::Revocations, revocations.as_ref());
    if recovered {
        state.generation = state
            .generation
            .checked_add(1)
            .ok_or(StorageError::GenerationOverflow)?;
        write_state(backend, &state)?;
    }

    Ok(LoadedDatabase {
        state,
        trust: trust.map(|candidate| candidate.bytes),
        revocations: revocations.map(|candidate| candidate.bytes),
        recovered,
    })
}

pub fn persist_snapshot<B: StorageBackend, V: SnapshotValidator>(
    backend: &mut B,
    validator: &mut V,
    state: &mut DatabaseState,
    kind: SnapshotKind,
    bytes: &[u8],
    etag: Etag,
    last_checked_at: u64,
) -> Result<Slot, StorageError> {
    let validated = validator.validate(kind, bytes)?;
    let current = metadata(state, kind);
    if current.snapshot_version != 0 && validated.snapshot_version <= current.snapshot_version {
        return Err(StorageError::SnapshotRollback);
    }

    let target = active_slot(state, kind).inactive();
    let path = slot_path(kind, target);
    backend.write_sync(path, bytes)?;
    let written = backend.read(path)?.ok_or(StorageError::WriteBackMismatch)?;
    if written != bytes {
        return Err(StorageError::WriteBackMismatch);
    }
    let written_metadata = validator.validate(kind, &written)?;
    if written_metadata != validated {
        return Err(StorageError::WriteBackMismatch);
    }

    let next_generation = state
        .generation
        .checked_add(1)
        .ok_or(StorageError::GenerationOverflow)?;
    let mut next = state.clone();
    next.generation = next_generation;
    *active_slot_mut(&mut next, kind) = target;
    *metadata_mut(&mut next, kind) = SnapshotMetadata {
        snapshot_version: validated.snapshot_version,
        generated_at: validated.generated_at,
        expires_at: validated.expires_at,
        last_checked_at,
        etag,
    };
    write_state(backend, &next)?;
    *state = next;
    Ok(target)
}

struct Candidate {
    slot: Slot,
    metadata: ValidatedSnapshot,
    bytes: Vec<u8>,
}

fn load_kind<B: StorageBackend, V: SnapshotValidator>(
    backend: &mut B,
    validator: &mut V,
    kind: SnapshotKind,
    state: Option<&DatabaseState>,
) -> Result<Option<Candidate>, StorageError> {
    let first = state.map_or(Slot::A, |state| active_slot(state, kind));
    let first_candidate = load_candidate(backend, validator, kind, first)?;
    if let (Some(state), Some(candidate)) = (state, first_candidate.as_ref())
        && metadata_matches(metadata(state, kind), candidate.metadata)
    {
        return Ok(first_candidate);
    }

    let second = first.inactive();
    let second_candidate = load_candidate(backend, validator, kind, second)?;
    Ok(newest(first_candidate, second_candidate))
}

fn load_candidate<B: StorageBackend, V: SnapshotValidator>(
    backend: &mut B,
    validator: &mut V,
    kind: SnapshotKind,
    slot: Slot,
) -> Result<Option<Candidate>, StorageError> {
    let Some(bytes) = backend.read(slot_path(kind, slot))? else {
        return Ok(None);
    };
    let Ok(metadata) = validator.validate(kind, &bytes) else {
        return Ok(None);
    };
    Ok(Some(Candidate {
        slot,
        metadata,
        bytes,
    }))
}

fn newest(first: Option<Candidate>, second: Option<Candidate>) -> Option<Candidate> {
    match (first, second) {
        (Some(first), Some(second)) => {
            if (
                second.metadata.snapshot_version,
                second.metadata.generated_at,
            ) > (first.metadata.snapshot_version, first.metadata.generated_at)
            {
                Some(second)
            } else {
                Some(first)
            }
        }
        (Some(candidate), None) | (None, Some(candidate)) => Some(candidate),
        (None, None) => None,
    }
}

fn apply_loaded(
    state: &mut DatabaseState,
    kind: SnapshotKind,
    candidate: Option<&Candidate>,
) -> bool {
    let old_slot = active_slot(state, kind);
    let old_metadata = metadata(state, kind).clone();
    let (slot, next_metadata) = match candidate {
        Some(candidate) => {
            let mut metadata = SnapshotMetadata {
                snapshot_version: candidate.metadata.snapshot_version,
                generated_at: candidate.metadata.generated_at,
                expires_at: candidate.metadata.expires_at,
                last_checked_at: 0,
                etag: Etag::none(),
            };
            if metadata_matches(&old_metadata, candidate.metadata) {
                metadata.last_checked_at = old_metadata.last_checked_at;
                metadata.etag = old_metadata.etag.clone();
            }
            (candidate.slot, metadata)
        }
        None => (Slot::A, SnapshotMetadata::default()),
    };
    *active_slot_mut(state, kind) = slot;
    *metadata_mut(state, kind) = next_metadata.clone();
    old_slot != slot || old_metadata != next_metadata
}

fn metadata_matches(stored: &SnapshotMetadata, validated: ValidatedSnapshot) -> bool {
    stored.snapshot_version == validated.snapshot_version
        && stored.generated_at == validated.generated_at
        && stored.expires_at == validated.expires_at
}

fn active_slot(state: &DatabaseState, kind: SnapshotKind) -> Slot {
    match kind {
        SnapshotKind::Trust => state.active_trust_slot,
        SnapshotKind::Revocations => state.active_revocation_slot,
    }
}

fn active_slot_mut(state: &mut DatabaseState, kind: SnapshotKind) -> &mut Slot {
    match kind {
        SnapshotKind::Trust => &mut state.active_trust_slot,
        SnapshotKind::Revocations => &mut state.active_revocation_slot,
    }
}

fn metadata(state: &DatabaseState, kind: SnapshotKind) -> &SnapshotMetadata {
    match kind {
        SnapshotKind::Trust => &state.trust,
        SnapshotKind::Revocations => &state.revocations,
    }
}

fn metadata_mut(state: &mut DatabaseState, kind: SnapshotKind) -> &mut SnapshotMetadata {
    match kind {
        SnapshotKind::Trust => &mut state.trust,
        SnapshotKind::Revocations => &mut state.revocations,
    }
}

fn slot_path(kind: SnapshotKind, slot: Slot) -> &'static str {
    match (kind, slot) {
        (SnapshotKind::Trust, Slot::A) => TRUST_A_PATH,
        (SnapshotKind::Trust, Slot::B) => TRUST_B_PATH,
        (SnapshotKind::Revocations, Slot::A) => REVOCATIONS_A_PATH,
        (SnapshotKind::Revocations, Slot::B) => REVOCATIONS_B_PATH,
    }
}

fn write_state<B: StorageBackend>(
    backend: &mut B,
    state: &DatabaseState,
) -> Result<(), StorageError> {
    let mut encoded = [0; STATE_LEN];
    state
        .encode(&mut encoded)
        .map_err(|_| StorageError::StateEncoding)?;
    backend.write_sync(STATE_PATH, &encoded)
}
