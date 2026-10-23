//! Process-local lifetime pins for native Handle labels. The caller serializes
//! access with its FD table while acquiring a pin or removing a descriptor.
//! No native rights are cloned, attenuated, or elevated by this bookkeeping.

#[derive(Clone, Copy)]
struct Slot {
    readers: usize,
    additional_owners: usize,
    retired: bool,
}

/// A single-use pin. Only the issuing book may release it.
#[must_use]
pub struct Pin {
    index: usize,
    owner: u64,
}

#[derive(Clone, Copy)]
struct Group {
    label: u64,
    owner: u64,
    readers: usize,
}
impl Group {
    const EMPTY: Self = Self {
        label: 0,
        owner: 0,
        readers: 0,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinError {
    InvalidLabel,
    InvalidOwner,
    Retired,
    Capacity,
}

pub struct Book<const N: usize> {
    slots: [Slot; N],
    // Bounded, allocation-free accounting for distinct (label, owner) pairs.
    // Open addressing avoids full-table scans in the usual lightly loaded case.
    groups: [Group; N],
}

impl<const N: usize> Book<N> {
    pub const fn new() -> Self {
        Self {
            slots: [Slot {
                readers: 0,
                additional_owners: 0,
                retired: false,
            }; N],
            groups: [Group::EMPTY; N],
        }
    }

    /// Share one already-owned native label between process-local FD owners.
    /// This creates no native reference and requires no DUPLICATE authority.
    /// Register each additional owner before publishing its descriptor.
    pub fn retain(&mut self, label: u64) -> Option<()> {
        let index = usize::try_from(label.checked_sub(1)?).ok()?;
        let slot = self.slots.get_mut(index)?;
        if slot.retired {
            return None;
        }
        slot.additional_owners = slot.additional_owners.checked_add(1)?;
        Some(())
    }

    /// Labels are one-based. Failure leaves every reference count unchanged.
    pub fn pin(&mut self, label: u64) -> Option<Pin> {
        self.pin_owned(label, 0).ok()
    }

    /// Attribute a lifetime pin to a stable caller-owned thread identity.
    /// Zero denotes an unattributed pin (the plain pin API). These tags confer
    /// no native authority. At most N distinct live pairs are tracked; any
    /// capacity/overflow failure leaves all counts unchanged.
    pub fn pin_owned(&mut self, label: u64, owner: u64) -> Result<Pin, PinError> {
        let index = label
            .checked_sub(1)
            .and_then(|v| usize::try_from(v).ok())
            .ok_or(PinError::InvalidLabel)?;
        let slot = self.slots.get(index).ok_or(PinError::InvalidLabel)?;
        if slot.retired {
            return Err(PinError::Retired);
        }
        let readers = slot.readers.checked_add(1).ok_or(PinError::Capacity)?;
        let bucket = self.bucket(label, owner).ok_or(PinError::Capacity)?;
        let group_readers = self.groups[bucket]
            .readers
            .checked_add(1)
            .ok_or(PinError::Capacity)?;
        self.groups[bucket] = Group {
            label,
            owner,
            readers: group_readers,
        };
        self.slots[index].readers = readers;
        Ok(Pin { index, owner })
    }

    /// Inspect pins belonging to disappearing threads, not the survivor.
    /// Unattributed pins count as foreign too. Reconciliation, if permitted,
    /// must use discard_for_fork on the child's private copy only.
    pub fn has_foreign_pins(&self, owner: u64) -> bool {
        self.groups
            .iter()
            .any(|group| group.label != 0 && (group.owner == 0 || group.owner != owner))
    }

    /// Child-only transition after VM capture, with the FD table and this book
    /// frozen. Only `owner` resumes in the child. Discard all other operation
    /// pins, including unattributed ones, but preserve every descriptor owner
    /// and the survivor's pins. Never run this on the parent's book or release
    /// a discarded Pin later: its owning stack must not resume in this image.
    ///
    /// `close` receives each retired native label whose last pin disappeared,
    /// once. It must perform only native reference disposal, not application
    /// callbacks or mutations of this book. No native authority is acquired.
    pub fn discard_for_fork(
        &mut self,
        owner: u64,
        mut close: impl FnMut(u64),
    ) -> Result<(), PinError> {
        if owner == 0 {
            return Err(PinError::InvalidOwner);
        }
        // Remove by key search rather than advancing an index: back-shift
        // deletion can move a wrapped bucket behind the previous cursor.
        while let Some(index) = self
            .groups
            .iter()
            .position(|group| group.label != 0 && group.owner != owner)
        {
            let group = self.groups[index];
            self.slots[group.label as usize - 1].readers -= group.readers;
            self.remove_group(index);
        }
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.retired && slot.readers == 0 {
                // Commit before disposal. Re-entry after a non-returning
                // disposal failure must not close a reused label twice.
                slot.retired = false;
                close(index as u64 + 1);
            }
        }
        Ok(())
    }

    fn home(label: u64, owner: u64) -> usize {
        (label.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ owner.wrapping_mul(0xbf58_476d_1ce4_e5b9))
            as usize
            % N
    }

    // Return the matching record or the first empty bucket. A full table can
    // still pin an existing pair; no allocation is required for duplicates.
    fn bucket(&self, label: u64, owner: u64) -> Option<usize> {
        if N == 0 {
            return None;
        }
        let mut index = Self::home(label, owner);
        for _ in 0..N {
            let group = self.groups[index];
            if group.label == 0 || (group.label == label && group.owner == owner) {
                return Some(index);
            }
            index = (index + 1) % N;
        }
        None
    }

    fn remove_group(&mut self, index: usize) {
        let distance = |from: usize, to: usize| if to >= from { to - from } else { N - from + to };
        let mut hole = index;
        self.groups[hole] = Group::EMPTY;
        let mut next = (hole + 1) % N;
        // Back-shift deletion avoids accumulating tombstones on the hot path.
        // Pins retain their key, not a bucket index, so moving groups is safe.
        for _ in 0..N.saturating_sub(1) {
            let group = self.groups[next];
            if group.label == 0 {
                break;
            }
            let home = Self::home(group.label, group.owner);
            if distance(home, hole) < distance(home, next) {
                self.groups[hole] = group;
                self.groups[next] = Group::EMPTY;
                hole = next;
            }
            next = (next + 1) % N;
        }
    }

    /// Remove one FD owner's reference. True means close the native reference
    /// now; false leaves it with another FD owner or outstanding operation.
    pub fn retire(&mut self, label: u64) -> Option<bool> {
        let index = usize::try_from(label.checked_sub(1)?).ok()?;
        let slot = self.slots.get_mut(index)?;
        if slot.retired {
            return None;
        }
        if slot.additional_owners != 0 {
            slot.additional_owners -= 1;
            return Some(false);
        }
        if slot.readers == 0 {
            return Some(true);
        }
        slot.retired = true;
        Some(false)
    }

    /// True transfers responsibility for the final native close to the caller.
    pub fn release(&mut self, pin: Pin) -> bool {
        let label = pin.index as u64 + 1;
        let bucket = self
            .bucket(label, pin.owner)
            .expect("pin belongs to this book");
        assert!(self.groups[bucket].label == label && self.groups[bucket].owner == pin.owner);
        self.groups[bucket].readers -= 1;
        if self.groups[bucket].readers == 0 {
            self.remove_group(bucket);
        }
        let slot = &mut self.slots[pin.index];
        slot.readers -= 1;
        if slot.readers == 0 && slot.retired {
            slot.retired = false;
            true
        } else {
            false
        }
    }
}
