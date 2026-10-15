//! Parent-only ownership of a prepared service transaction across VM capture.
use super::*;

pub(super) struct Preparation {
    client: &'static PosixClient<SyscallEndpointTransport>,
    token: Option<u64>,
}

impl Preparation {
    pub(super) fn new(
        client: &'static PosixClient<SyscallEndpointTransport>,
    ) -> Result<Self, c_int> {
        let token = client.prepare_fork().map_err(map_posix_client_error)?;
        Ok(Self {
            client,
            token: Some(token),
        })
    }

    pub(super) fn commit(&mut self, child: ObjectHandleAttachment<u32>) -> Result<(), c_int> {
        self.client
            .commit_fork(self.token.expect("parent-owned preparation"), child)
            .map_err(map_posix_client_error)?;
        self.token = None;
        Ok(())
    }

    pub(super) fn disarm_child(&mut self) {
        // The copied token still belongs to the parent, not this new process.
        self.token = None;
    }

    fn cancel(&mut self) -> Result<(), c_int> {
        let Some(token) = self.token else {
            return Ok(());
        };
        match self.client.cancel_fork(token) {
            Ok(()) | Err(PosixClientError::Remote(posix_protocol::STATUS_ESRCH)) => {
                // A previous cancel or an ambiguously replied commit consumed
                // this never-reused token. Transport ESRCH is NOT that proof.
                self.token = None;
                Ok(())
            }
            Err(error) => Err(map_posix_client_error(error)),
        }
    }
}

impl Drop for Preparation {
    fn drop(&mut self) {
        if self.token.is_none() {
            return;
        }
        let _delivery = defer_native_delivery();
        let mut reported = false;
        // Retain the exact token until cancellation is confirmed. Do not turn
        // a failed IPC or a fixed retry count into a leaked preparation.
        while let Err(error) = self.cancel() {
            if error != EAGAIN && error != EINTR && !reported {
                let message = b"newlib: fork policy cleanup pending; retaining token for retry\n";
                let _ = syscall::raw_syscall2(
                    syscall::SyscallNumber::DebugWrite,
                    message.as_ptr() as u64,
                    message.len() as u64,
                );
                reported = true;
            }
            if syscall_errno(syscall::raw_syscall1(syscall::SyscallNumber::Sleep, 10)).is_err() {
                let _ = syscall::raw_syscall0(syscall::SyscallNumber::ThreadYield);
            }
        }
    }
}
