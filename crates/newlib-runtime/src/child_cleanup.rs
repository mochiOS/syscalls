use mochios_posix_client::newlib_errno::{EAGAIN, ESRCH};

pub trait Backend {
    fn is_exited(&mut self, handle: u64) -> Result<bool, i32>;
    fn terminate(&mut self, handle: u64) -> Result<(), i32>;
    fn reclaim_registration(&mut self, handle: u64) -> Result<(), i32>;
    fn close(&mut self, handle: u64) -> Result<(), i32>;
}

/// A failed creation's reference remains owned until every cleanup stage is
/// confirmed. In particular, a lost registration reply is not proof that the
/// server did not register the child. No PID lookup can replace this owner.
pub struct Cleanup {
    handle: u64,
    exit_confirmed: bool,
    registration_reclaimed: bool,
    closed: bool,
}

impl Cleanup {
    pub fn new(handle: u64, registration_attempted: bool) -> Self {
        Self {
            handle,
            exit_confirmed: false,
            registration_reclaimed: !registration_attempted,
            closed: false,
        }
    }

    /// Advance through confirmed stages only. The caller must retain this
    /// transaction and retry on error, not discard its native reference.
    pub fn retry(&mut self, backend: &mut impl Backend) -> Result<(), i32> {
        if self.closed {
            return Ok(());
        }
        if !self.exit_confirmed {
            if !backend.is_exited(self.handle)? {
                backend.terminate(self.handle)?;
                if !backend.is_exited(self.handle)? {
                    return Err(EAGAIN);
                }
            }
            self.exit_confirmed = true;
        }
        if !self.registration_reclaimed {
            match backend.reclaim_registration(self.handle) {
                Ok(()) | Err(ESRCH) => self.registration_reclaimed = true,
                Err(error) => return Err(error),
            }
        }
        backend.close(self.handle)?;
        self.closed = true;
        Ok(())
    }
}
