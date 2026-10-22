//! Operation-local ownership through child creation and exec-status waiting.
use super::*;

pub(super) struct Resources {
    read: Option<u32>,
    write: Option<u32>,
    child: Option<(u64, bool)>,
    startup: Option<CloneStartup>,
    preparation: Option<fork_policy::Preparation>,
}

impl Resources {
    fn for_fork() -> Result<Self, c_int> {
        // fork needs startup acknowledgement, but not an exec-status stream.
        Ok(Self {
            read: None,
            write: None,
            child: None,
            startup: Some(CloneStartup::new()?),
            preparation: None,
        })
    }

    fn new() -> Result<Self, c_int> {
        let pair = create_spawn_status_stream()?;
        let mut resources = Self {
            read: (pair.read != 0).then_some(pair.read),
            write: (pair.write != 0 && pair.write != pair.read).then_some(pair.write),
            child: None,
            startup: None,
            preparation: None,
        };
        if pair.read == 0 || pair.write == 0 || pair.read == pair.write {
            resources.close_streams();
            return Err(EIO);
        }
        resources.startup = Some(CloneStartup::new()?);
        Ok(resources)
    }

    // Called only with native delivery deferred across Handle publication.
    pub(super) fn track_child(&mut self, child: Option<(u64, bool)>) {
        self.child = child;
    }

    pub(super) fn clone_registered(
        &mut self,
    ) -> Result<(u64, FdTable<FdObject>, Option<u32>), c_int> {
        let child = &mut self.child;
        clone_registered_process_owned(
            self.startup.as_mut().ok_or(EIO)?,
            &mut self.preparation,
            |value| *child = value,
        )
    }

    pub(super) fn child_writer(&mut self) -> Result<(), c_int> {
        let _delivery = defer_native_delivery();
        if let Some(handle) = self.read.take() {
            close_object_handle(handle);
        }
        self.write.map(|_| ()).ok_or(EBADF)
    }

    pub(super) fn fail(&mut self, error: c_int) -> ! {
        let _delivery = defer_native_delivery();
        let writer = self.write.take().unwrap_or_else(|| process_exit(EIO));
        report_spawn_error(writer, error)
    }

    pub(super) fn wait(&mut self) -> Result<mochios_posix_client::spawn::ExecStatus, c_int> {
        {
            let _delivery = defer_native_delivery();
            if let Some(handle) = self.write.take() {
                close_object_handle(handle);
            }
        }
        // Keep the read reference and child registered while callbacks run.
        let result = read_spawn_status(self.read.ok_or(EBADF)?);
        let _delivery = defer_native_delivery();
        if let Some(handle) = self.read.take() {
            close_object_handle(handle);
        }
        result
    }

    pub(super) fn publish(&mut self, process_id: u64, output: *mut c_int) -> c_int {
        let _delivery = defer_native_delivery();
        let Some((handle, registered)) = self.child else {
            return EIO;
        };
        if !registered {
            return EIO;
        }
        let Ok(handle) = u32::try_from(handle) else {
            return EOVERFLOW;
        };
        // The nested publication owner is installed before delivery reopens.
        self.track_child(None);
        spawn_output::publish(process_id, handle, output)
    }

    fn finish_fork(
        &mut self,
        process_id: u64,
        process_handle: Option<u32>,
    ) -> Result<c_int, c_int> {
        let _delivery = defer_native_delivery();
        let pid = c_int::try_from(process_id).map_err(|_| EOVERFLOW)?;
        match (pid, process_handle, self.child) {
            (0, None, None) => Ok(0),
            (pid, Some(handle), Some((owned, true))) if pid > 0 && owned == u64::from(handle) => {
                // fork publishes its positive PID by return value, not through
                // caller memory. Keep the child owned until this infallible
                // handoff; only this parent's native reference is discarded.
                close_object_handle(handle);
                self.track_child(None);
                Ok(pid)
            }
            _ => Err(EIO),
        }
    }

    fn close_streams(&mut self) {
        for handle in [self.read.take(), self.write.take()].into_iter().flatten() {
            close_object_handle(handle);
        }
    }
}

impl Drop for Resources {
    fn drop(&mut self) {
        let _delivery = defer_native_delivery();
        self.close_streams();
        drop(self.startup.take());
        drop(self.preparation.take());
        if let Some((handle, registered)) = self.child.take() {
            cleanup_failed_child(handle, registered);
        }
    }
}

pub(super) fn with(operation: impl FnOnce(&mut Resources) -> c_int) -> c_int {
    match io_resources::with(Resources::new, |resources| Ok(operation(resources))) {
        Ok(status) => status,
        Err(error) => error,
    }
}

pub(super) fn fork() -> Result<c_int, c_int> {
    io_resources::with(Resources::for_fork, |resources| {
        let (pid, _, process_handle) = resources.clone_registered()?;
        resources.finish_fork(pid, process_handle)
    })
}
