//! Process-local lifetime pins for native Handle labels. The caller serializes
//! access with its FD table while acquiring a pin or removing a descriptor.
//! No native rights are cloned, attenuated, or elevated by this bookkeeping.

#[derive(Clone, Copy)]
struct Slot {
    readers: usize,
    retired: bool,
}

/// A single-use pin. Only the issuing book may release it.
#[must_use]
pub struct Pin {
    index: usize,
}

pub struct Book<const N: usize> {
    slots: [Slot; N],
}

impl<const N: usize> Book<N> {
    pub const fn new() -> Self {
        Self {
            slots: [Slot {
                readers: 0,
                retired: false,
            }; N],
        }
    }

    /// Labels are one-based. Failure leaves every reference count unchanged.
    pub fn pin(&mut self, label: u64) -> Option<Pin> {
        let index = usize::try_from(label.checked_sub(1)?).ok()?;
        let slot = self.slots.get_mut(index)?;
        if slot.retired {
            return None;
        }
        slot.readers = slot.readers.checked_add(1)?;
        Some(Pin { index })
    }

    /// Remove the table's ownership. True means close the native reference
    /// now; false defers that close to the last outstanding operation.
    pub fn retire(&mut self, label: u64) -> Option<bool> {
        let index = usize::try_from(label.checked_sub(1)?).ok()?;
        let slot = self.slots.get_mut(index)?;
        if slot.retired {
            return None;
        }
        if slot.readers == 0 {
            return Some(true);
        }
        slot.retired = true;
        Some(false)
    }

    /// True transfers responsibility for the final native close to the caller.
    pub fn release(&mut self, pin: Pin) -> bool {
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
