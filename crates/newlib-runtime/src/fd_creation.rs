//! Rollback owners for descriptor creation, shared by sockets, pipes and PTYs.
use super::*;

pub(super) struct PendingPair(pub(super) [FdReservation; 2]);
impl PendingPair {
    pub(super) fn copy_descriptors(&self, output: *mut c_int) -> Result<(), c_int> {
        let mut bytes = [0; 2 * core::mem::size_of::<c_int>()];
        for (field, reservation) in bytes
            .chunks_exact_mut(core::mem::size_of::<c_int>())
            .zip(&self.0)
        {
            field.copy_from_slice(&reservation.descriptor().to_ne_bytes());
        }
        user_copy::write(output.cast(), &bytes)
    }
}
impl Drop for PendingPair {
    fn drop(&mut self) {
        let mut state = state();
        for reservation in &self.0 {
            state.fds.cancel_reservation(reservation);
        }
    }
}

pub(super) struct PendingHandles<const N: usize> {
    pub(super) handles: [ObjectHandleAttachment<u32>; N],
    pub(super) installed: bool,
}
impl<const N: usize> Drop for PendingHandles<N> {
    fn drop(&mut self) {
        if !self.installed {
            for handle in self.handles {
                close_object_handle(handle.handle);
            }
        }
    }
}
