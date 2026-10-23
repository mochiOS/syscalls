//! Process-local timer notification values. Only the opaque token crosses
//! IPC; values are copied locally before calling any application handler.
//! Synchronize externally. After address-space clone, clear the child's table
//! before enabling notification dispatch: POSIX timers are not inherited.

/// Registry-local bookkeeping, not a Handle or authority. Use only with the
/// registry that issued it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token(u64);
impl Token {
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Full,
    Exhausted,
    InvalidToken,
    AlreadyBound,
    InvalidTimer,
    DuplicateTimer,
    InvalidOwner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveError {
    UnknownToken,
    StaleToken,
    UnboundToken,
    WrongTimer,
}

#[derive(Clone, Copy)]
struct Entry<V: Copy> {
    token: Token,
    timer: u64,
    value: V,
    owner: Option<u64>,
}

/// Allocation-free storage with strictly non-reused, full-width wire tokens.
#[derive(Clone)]
pub struct Registry<V: Copy, const N: usize> {
    entries: [Option<Entry<V>>; N],
    last_token: u64,
}

impl<V: Copy, const N: usize> Registry<V, N> {
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            last_token: 0,
        }
    }

    /// Reserve before creation RPC. Bind only after receiving its validated
    /// server ID; failed creation can cancel this reservation without IPC.
    pub fn reserve(&mut self, value: V) -> Result<Token, Error> {
        self.reserve_for(value, None)
    }

    /// Process-local lifetime label; grants no authority and is never sent
    /// over IPC. Use for notifications which disappear with this local owner.
    pub fn reserve_owned(&mut self, value: V, owner: u64) -> Result<Token, Error> {
        if owner == 0 {
            return Err(Error::InvalidOwner);
        }
        self.reserve_for(value, Some(owner))
    }

    fn reserve_for(&mut self, value: V, owner: Option<u64>) -> Result<Token, Error> {
        let index = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Full)?;
        let raw = self.last_token.checked_add(1).ok_or(Error::Exhausted)?;
        let token = Token(raw);
        self.entries[index] = Some(Entry {
            token,
            timer: 0,
            value,
            owner,
        });
        self.last_token = raw;
        Ok(token)
    }

    fn index(&self, token: Token) -> Result<usize, Error> {
        self.entries
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|entry| entry.token == token))
            .ok_or(Error::InvalidToken)
    }

    /// Used for default sigevents whose final value is the returned timer ID.
    /// Once bound, a notification's value cannot be silently replaced.
    pub fn update_reserved(&mut self, token: Token, value: V) -> Result<(), Error> {
        let index = self.index(token)?;
        let entry = self.entries[index].as_mut().unwrap();
        if entry.timer != 0 {
            return Err(Error::AlreadyBound);
        }
        entry.value = value;
        Ok(())
    }

    pub fn bind(&mut self, token: Token, timer: u64) -> Result<(), Error> {
        if timer == 0 {
            return Err(Error::InvalidTimer);
        }
        let index = self.index(token)?;
        if self.entries[index].as_ref().unwrap().timer != 0 {
            return Err(Error::AlreadyBound);
        }
        if self
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.timer == timer)
        {
            return Err(Error::DuplicateTimer);
        }
        self.entries[index].as_mut().unwrap().timer = timer;
        Ok(())
    }

    pub fn cancel(&mut self, token: Token) -> Result<V, Error> {
        let index = self.index(token)?;
        if self.entries[index].as_ref().unwrap().timer != 0 {
            return Err(Error::AlreadyBound);
        }
        Ok(self.entries[index].take().unwrap().value)
    }

    /// Call after authoritative deletion. Already copied values remain valid
    /// snapshots; late notifications can be distinguished from unknown tokens.
    /// This table itself decides neither delivery nor cancellation policy.
    pub fn retire(&mut self, timer: u64) -> Option<V> {
        if timer == 0 {
            return None;
        }
        let index = self
            .entries
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|entry| entry.timer == timer))?;
        self.entries[index].take().map(|entry| entry.value)
    }

    /// Retire the disappearing owner's notification values, preserving other
    /// owners, process-lifetime values and the non-reused token high-water mark.
    pub fn retire_owner(&mut self, owner: u64) {
        for entry in &mut self.entries {
            if entry
                .as_ref()
                .is_some_and(|entry| entry.owner == Some(owner))
            {
                *entry = None;
            }
        }
    }

    /// Match both identities, never fall back to a slot number or timer ID.
    /// Return a copy, not a reference held across a handler/delete/re-entry.
    pub fn resolve(&self, timer: u64, raw_token: u64) -> Result<V, ResolveError> {
        if raw_token == 0 || raw_token > self.last_token {
            return Err(ResolveError::UnknownToken);
        }
        let entry = self
            .entries
            .iter()
            .flatten()
            .find(|entry| entry.token.raw() == raw_token)
            .ok_or(ResolveError::StaleToken)?;
        if entry.timer == 0 {
            return Err(ResolveError::UnboundToken);
        }
        if timer == 0 || entry.timer != timer {
            return Err(ResolveError::WrongTimer);
        }
        Ok(entry.value)
    }

    /// No value/notification is inherited. Preserve the high-water mark so a
    /// copied old token cannot resolve through a new reservation in the child.
    pub fn clear_for_fork(&mut self) {
        self.entries.fill(None);
    }
}

impl<V: Copy, const N: usize> Default for Registry<V, N> {
    fn default() -> Self {
        Self::new()
    }
}
