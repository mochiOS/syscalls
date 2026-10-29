//! Native mechanisms used by the C resolver. Resource labels are returned only
//! from explicitly delegated endpoints or the caller's POSIX namespace open.
use super::{Error, Io, interfaces, resolver};
use crate::*;

pub(crate) struct Native {
    caught: Option<u64>,
}
impl Native {
    pub const fn new() -> Self {
        Self { caught: None }
    }
    fn check(&mut self) -> Result<(&'static ThreadControl, u64), Error> {
        let (_, control) = register_current_thread().ok_or(Error::System(-11))?;
        let current = control.nonrestart_signal_generation.load(Ordering::Acquire);
        let caught = *self.caught.get_or_insert(current);
        if io_cancellation_requested(control) || current != caught {
            return Err(Error::System(-4));
        }
        Ok((control, caught))
    }
}
fn system(errno: c_int) -> Error {
    Error::System(mochios_posix_client::newlib_errno::to_status(errno))
}
fn native(error: syscall::SysError) -> Error {
    system(map_kernel_errno(error.raw()))
}
fn client(error: PosixClientError<syscall::SysError>) -> Error {
    match error {
        PosixClientError::Remote(-11) => Error::Again,
        PosixClientError::Remote(-12) => Error::Memory,
        PosixClientError::Remote(status) => Error::System(status),
        PosixClientError::Transport(error) => native(error),
        _ => Error::Fail,
    }
}
impl Io for Native {
    fn endpoint(&mut self) -> Result<u32, Error> {
        self.check()?;
        Ok(posix_client()
            .map_err(client)?
            .network_endpoint(close_object_handle)
            .map_err(client)?
            .handle)
    }
    fn factory(&mut self, endpoint: u32) -> Result<u32, Error> {
        self.check()?;
        match resolver::acquire(
            &SyscallEndpointTransport::new(endpoint),
            resolver::Limits {
                scopes: resolver::ALL_SCOPES,
                maximum_timeout: resolver::MAX_TIMEOUT,
            },
        ) {
            Ok(factory) => Ok(factory.handle),
            Err(PosixClientError::Remote(-24)) => Err(Error::Again),
            Err(e) => Err(client(e)),
        }
    }
    fn start(
        &mut self,
        endpoint: u32,
        factory: u32,
        kind: resolver::Kind,
        name: resolver::Name<'_>,
        timeout: u32,
    ) -> Result<Option<u32>, Error> {
        self.check()?;
        match resolver::start(
            &SyscallEndpointTransport::new(endpoint),
            ObjectHandleAttachment {
                handle: factory,
                rights: resolver::FACTORY_RIGHTS,
            },
            kind,
            name,
            timeout,
        ) {
            Ok(job) => Ok(Some(job.handle)),
            Err(PosixClientError::Remote(-24)) => Ok(None),
            Err(e) => Err(client(e)),
        }
    }
    fn observe(&mut self, job: u32) -> Result<resolver::Observation, Error> {
        self.check()?;
        resolver::observe(&resolver::NativeIo, job).map_err(client)
    }
    fn snapshot<'a>(
        &mut self,
        job: u32,
        kind: resolver::Kind,
        name: resolver::Name<'_>,
        out: &'a mut [u8],
    ) -> Result<resolver::ResultView<'a>, Error> {
        self.check()?;
        resolver::snapshot(&resolver::NativeIo, job, kind, name, out).map_err(client)
    }
    fn wait(&mut self, job: u32, deadline: u64) -> Result<(), Error> {
        let (control, caught) = self.check()?;
        let entry = object_entry(
            u64::from(job),
            resolver::JOB_RIGHTS,
            FdKind::ObjectSocket,
            2,
        );
        match wait_for_handle_capacity(
            entry,
            syscall::HANDLE_SIGNAL_READABLE | syscall::HANDLE_SIGNAL_PEER_CLOSED,
            control,
            caught,
            0,
            deadline,
        ) {
            Ok(_) => {
                self.check()?;
                Ok(())
            }
            Err(EAGAIN) => Ok(()),
            Err(e) => Err(system(e)),
        }
    }
    fn now(&mut self) -> Result<u64, Error> {
        self.check()?;
        monotonic_nanoseconds().map_err(system)
    }
    fn retry(&mut self) -> Result<(), Error> {
        self.check()?;
        syscall::call0(syscall::SyscallNumber::ThreadYield).map_err(native)?;
        Ok(())
    }
    fn interfaces<'a>(
        &mut self,
        endpoint: u32,
        out: &'a mut [u8],
    ) -> Result<interfaces::Snapshot<'a>, Error> {
        self.check()?;
        // Unexpected reply attachments must be retired before a C handler can
        // abandon the temporary transport envelope. This is a bounded query.
        let _native = defer_native_delivery();
        interfaces::snapshot(&SyscallEndpointTransport::new(endpoint), out).map_err(client)
    }
    fn open(&mut self, path: &[u8]) -> Result<u32, Error> {
        self.check()?;
        let opened = posix_client()
            .map_err(client)?
            .open_at(OpenAtBase::ProcessRoot, posix_protocol::OPEN_READ, 0, path)
            .map_err(client)?;
        if opened.rights & mnu_abi::HANDLE_RIGHT_READ == 0 {
            close_object_handle(opened.handle);
            return Err(Error::Fail);
        }
        Ok(opened.handle)
    }
    fn read(&mut self, file: u32, offset: u64, out: &mut [u8]) -> Result<usize, Error> {
        self.check()?;
        let n = syscall::call4(
            syscall::SyscallNumber::HandleReadAt,
            u64::from(file),
            out.as_mut_ptr() as u64,
            out.len() as u64,
            offset,
        )
        .map_err(native)?;
        usize::try_from(n)
            .ok()
            .filter(|n| *n <= out.len())
            .ok_or(Error::Fail)
    }
    fn close(&mut self, handle: u32) {
        close_object_handle(handle);
    }
}
