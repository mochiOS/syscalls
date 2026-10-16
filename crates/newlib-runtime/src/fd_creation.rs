//! Rollback owners for descriptor creation, shared by sockets and pipes.
use super::*;

pub(super) struct PendingPair(pub(super) [FdReservation; 2]);
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
