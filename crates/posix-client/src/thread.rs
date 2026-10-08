//! Process-local POSIX thread identity.
//!
//! Native thread identifiers are kernel diagnostics, not POSIX `pthread_t`
//! values.  A generation-bearing token prevents a stale `pthread_t` from
//! naming a later thread after its runtime slot is reused.

pub const MAX_THREADS: usize = 64;
const SLOT_BITS: u32 = 6;
const SLOT_MASK: u32 = (1 << SLOT_BITS) - 1;
const MAX_GENERATION: u32 = u32::MAX >> SLOT_BITS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ThreadToken(u32);

impl ThreadToken {
    pub fn new(slot: usize, generation: u32) -> Option<Self> {
        if slot >= MAX_THREADS || generation == 0 || generation > MAX_GENERATION {
            return None;
        }
        let encoded_slot = u32::try_from(slot).ok()?;
        Some(Self((generation << SLOT_BITS) | encoded_slot))
    }

    pub const fn from_raw(raw: u32) -> Option<Self> {
        let generation = raw >> SLOT_BITS;
        if generation == 0 {
            None
        } else {
            Some(Self(raw))
        }
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    pub const fn slot(self) -> usize {
        (self.0 & SLOT_MASK) as usize
    }

    pub const fn generation(self) -> u32 {
        self.0 >> SLOT_BITS
    }
}

pub const fn next_generation(current: u32) -> u32 {
    let next = current.wrapping_add(1) & MAX_GENERATION;
    if next == 0 { 1 } else { next }
}
