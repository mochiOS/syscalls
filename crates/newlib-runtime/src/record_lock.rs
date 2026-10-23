//! Process-owned record locks. Gate ordering is lifecycle -> this gate ->
//! allocator/policy/STATE; no STATE or borrow-book lock crosses policy IPC.
use super::*;
use posix_protocol::record_lock::{Kind, Operation, Origin, Reply, Request};

static GATE: RuntimeMutex<()> = RuntimeMutex::new(());
static EXEC_CLEANUP: AtomicU64 = AtomicU64::new(0);

pub(super) fn gate() -> RuntimeMutexGuard<'static, ()> {
    GATE.lock()
}
pub(super) fn active() -> bool {
    // Failure conservatively falls back to authoritative service IPC, never
    // treating an unreadable process policy as "no locks".
    resource_policy::record_locks().unwrap_or(true)
}
pub(super) fn reset_for_fork() {
    EXEC_CLEANUP.store(0, Ordering::Release);
}

pub(super) use crate::record_lock_memory::Flock;

fn apply(entry: FdEntry, request: Request) -> Result<Reply, c_int> {
    posix_client()
        .map_err(map_posix_client_error)?
        .record_lock(
            ObjectHandleAttachment {
                handle: u32::try_from(entry.handle.lower_handle).map_err(|_| EBADF)?,
                rights: entry.rights,
            },
            request,
        )
        .map_err(map_posix_client_error)
}

pub(super) fn fcntl(fd: c_int, command: c_int, input: *mut Flock) -> Result<c_int, c_int> {
    let _gate = gate();
    let lease = with_fd_entry(fd)?;
    if lease.handle.kind != FdKind::ObjectFile {
        return Err(EBADF);
    }
    let request = record_lock_memory::read_request(command, input)?;
    match request.operation {
        Operation::Set(Kind::Read)
            if !mochios_posix_client::fd::access_allows_read(lease.handle.open_flags as u32) =>
        {
            return Err(EBADF);
        }
        Operation::Set(Kind::Write)
            if !mochios_posix_client::fd::access_allows_write(lease.handle.open_flags as u32) =>
        {
            return Err(EBADF);
        }
        _ => {}
    }
    // A waiting operation needs cancellation/interruption admission; never
    // silently turn F_SETLKW into a nonblocking F_SETLK.
    if command == F_SETLKW && matches!(request.operation, Operation::Set(_)) {
        return Err(ENOSYS);
    }
    cancel_exec()?;
    let reply = apply(*lease, request)?;
    if command == F_GETLK {
        record_lock_memory::write_reply(input, reply)?;
    }
    Ok(0)
}

/// Caller holds GATE. Keep the source reference alive across remote fstat.
pub(super) fn release(entry: FdEntry) -> Result<(), c_int> {
    if active() && entry.handle.kind == FdKind::ObjectFile {
        apply(
            entry,
            Request {
                operation: Operation::ReleaseFile,
                origin: Origin::Start,
                start: 0,
                length: 0,
            },
        )?;
    }
    Ok(())
}

/// Caller holds GATE; zero-lock closes do not capture a reference or send IPC.
pub(super) fn before_close(fd: c_int) -> Result<(), c_int> {
    // Pipes, sockets and directories have no POSIX record-lock state. Avoid
    // lazy policy discovery for these native-only closes as well.
    {
        let state = state();
        let entry = state.fds.get(fd).ok_or(EBADF)?;
        if entry.handle.kind != FdKind::ObjectFile {
            return Ok(());
        }
    }
    if !active() {
        return Ok(());
    }
    let entry = with_fd_entry(fd)?;
    cancel_exec()?;
    release(*entry)
}

/// A failed cancellation remains recorded for retry by the next gated policy
/// operation. No Drop performs service IPC and no stale token is forgotten.
pub(super) fn cancel_exec() -> Result<(), c_int> {
    let token = EXEC_CLEANUP.load(Ordering::Acquire);
    if token == 0 {
        return Ok(());
    }
    match posix_client()
        .map_err(map_posix_client_error)?
        .cancel_record_lock_exec(token)
    {
        Ok(()) | Err(PosixClientError::Remote(posix_protocol::STATUS_ESRCH)) => {
            EXEC_CLEANUP.store(0, Ordering::Release);
            Ok(())
        }
        Err(error) => Err(map_posix_client_error(error)),
    }
}

/// Caller has stabilized FD mutations with GATE and owns snapshot leases.
pub(super) fn prepare_exec(fds: &FdTable<FdObject>) -> Result<(), c_int> {
    cancel_exec()?;
    if !active() {
        return Ok(());
    }
    let mut batch = [ObjectHandleAttachment {
        handle: 0,
        rights: 0,
    }; mochios_posix_client::MAX_OBJECT_HANDLES];
    let mut used = 0;
    let mut token = None;
    let client = posix_client().map_err(map_posix_client_error)?;
    for fd in 0..MAX_FDS {
        let Some(entry) = fds.get(fd as c_int) else {
            continue;
        };
        if entry.descriptor_flags & FD_CLOEXEC as u32 == 0
            || entry.handle.kind != FdKind::ObjectFile
        {
            continue;
        }
        batch[used] = ObjectHandleAttachment {
            handle: entry.handle.lower_handle as u32,
            rights: entry.rights,
        };
        used += 1;
        if used == batch.len() {
            token = client
                .prepare_record_lock_exec(&batch, token)
                .map_err(map_posix_client_error)?;
            EXEC_CLEANUP.store(token.unwrap_or(0), Ordering::Release);
            used = 0;
        }
    }
    if used != 0 {
        token = client
            .prepare_record_lock_exec(&batch[..used], token)
            .map_err(map_posix_client_error)?;
        EXEC_CLEANUP.store(token.unwrap_or(0), Ordering::Release);
    }
    Ok(())
}

/// A cloned reference and a destination reservation, both owned until commit.
/// The old destination lease prevents native disposal from failing mid-commit.
struct Duplicate {
    reservation: mochios_posix_client::fd::FdReplacement,
    new: Option<FdObject>,
    old: Option<fd_lease::Lease>,
}
impl Drop for Duplicate {
    fn drop(&mut self) {
        {
            state().fds.cancel_replacement(&self.reservation);
        }
        if let Some(object) = self.new.take() {
            if object.close_owned {
                close_object_handle(object.lower_handle as u32);
            }
        }
    }
}

pub(super) fn duplicate(old_fd: c_int, new_fd: c_int, limit: c_int) -> Result<c_int, c_int> {
    let _gate = gate();
    if old_fd < 0 || new_fd < 0 || old_fd as usize >= MAX_FDS || new_fd as usize >= MAX_FDS {
        return Err(EBADF);
    }
    let mut table = state();
    let source = table.fds.get(old_fd).ok_or(EBADF)?;
    if old_fd == new_fd {
        return Ok(new_fd);
    }
    if new_fd >= limit {
        return Err(EBADF);
    }
    let old = table
        .fds
        .get(new_fd)
        .map(fd_lease::Lease::new)
        .transpose()?;
    let (reservation, _) = table
        .fds
        .reserve_replacement(new_fd)
        .map_err(|error| match error {
            FdError::BusyDescriptor => EBUSY,
            _ => EBADF,
        })?;
    let new = match RuntimeFdOps.clone_handle(source.handle, source.rights) {
        Ok(new) => new,
        Err(error) => {
            table.fds.cancel_replacement(&reservation);
            return Err(error);
        }
    };
    drop(table);
    let mut pending = Duplicate {
        reservation,
        new: Some(new),
        old,
    };
    cancel_exec()?;
    if let Some(old) = &pending.old {
        release(**old)?;
    }
    let mut table = state();
    let displaced = table
        .fds
        .commit_replacement(
            &pending.reservation,
            FdEntry {
                handle: new,
                rights: source.rights,
                descriptor_flags: source.descriptor_flags & !FD_CLOEXEC as u32,
            },
        )
        .map_err(|_| EIO)?;
    pending.new = None;
    if let Some(old) = displaced {
        fd_lease::retire(old.handle)?;
    }
    drop(table);
    Ok(new_fd)
}
