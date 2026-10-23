//! Process-local, non-reused IDs for explicitly selected pthread CPU clocks.
//! These records grant no native authority and retain no kernel references.

pub const FIRST_ID: u64 = 1 << 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub thread: u32,
    pub native_thread: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidTarget,
    Full,
    Exhausted,
}

#[derive(Clone, Copy)]
struct Entry {
    id: u64,
    target: Target,
}

#[derive(Clone)]
pub struct Registry<const N: usize> {
    entries: [Option<Entry>; N],
    last: u64,
}

impl<const N: usize> Registry<N> {
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            last: FIRST_ID - 1,
        }
    }

    pub fn get_or_insert(&mut self, target: Target) -> Result<u64, Error> {
        if crate::thread::ThreadToken::from_raw(target.thread).is_none()
            || target.native_thread == 0
        {
            return Err(Error::InvalidTarget);
        }
        if let Some(entry) = self
            .entries
            .iter()
            .flatten()
            .find(|entry| entry.target == target)
        {
            return Ok(entry.id);
        }
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(Error::Full)?;
        let id = self.last.checked_add(1).ok_or(Error::Exhausted)?;
        *slot = Some(Entry { id, target });
        self.last = id;
        Ok(id)
    }

    pub fn resolve(&self, id: u64) -> Option<Target> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.id == id)
            .map(|entry| entry.target)
    }

    /// Called with runtime lifetime metadata, not caller-supplied liveness.
    pub fn retain(&mut self, mut live: impl FnMut(Target) -> bool) {
        for entry in &mut self.entries {
            if entry.as_ref().is_some_and(|entry| !live(entry.target)) {
                *entry = None;
            }
        }
    }

    pub fn retire_native(&mut self, native_thread: u64) {
        self.retain(|target| target.native_thread != native_thread);
    }

    /// Invalidate copied IDs without letting a later child clock reuse one.
    pub fn clear_for_fork(&mut self) {
        self.entries.fill(None);
    }
}

impl<const N: usize> Default for Registry<N> {
    fn default() -> Self {
        Self::new()
    }
}
