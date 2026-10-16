//! Name snapshots, pending FD slots and native replies share one tracked owner.
use super::*;
use mochios_posix_protocol::shared_memory as wire;

struct Resources {
    reply: object_reply::Reply,
    reservation: Option<PendingFdReservation>,
    name: [u8; wire::MAX_NAME_BYTES + 1],
    length: usize,
}

impl Resources {
    fn empty() -> Self {
        Self {
            reply: object_reply::Reply::new(None),
            reservation: None,
            name: [0; wire::MAX_NAME_BYTES + 1],
            length: 0,
        }
    }

    fn capture(&mut self, pointer: *const c_char) -> Result<(), c_int> {
        if pointer.is_null() {
            return Err(EFAULT);
        }
        for index in 0..=self.name.len() {
            let byte = unsafe { pointer.add(index).read() };
            if byte == 0 {
                self.length = index;
                return Ok(());
            }
            if index == self.name.len() {
                return Err(ENAMETOOLONG);
            }
            self.name[index] = byte as u8;
        }
        unreachable!()
    }

    fn execute(
        &mut self,
        prepared: &mochios_posix_client::shared_memory::PreparedNamespace,
        endpoint: u32,
    ) -> Result<Option<ObjectHandleAttachment<u32>>, c_int> {
        let mut response = [0; posix_protocol::HEADER_LEN + 1];
        let length = self
            .reply
            .call(endpoint, prepared.request(), &mut response)?;
        prepared
            .validate::<u32, syscall::SysError>(&response[..length], &self.reply.handles()?)
            .map_err(map_posix_client_error)
    }
}

pub(super) fn open(pointer: *const c_char, flags: c_int, mode: u32) -> Result<c_int, c_int> {
    let options = mochios_posix_client::shared_memory::newlib_open_options(flags).ok_or(EINVAL)?;
    io_resources::with_initialized(
        || Ok(Resources::empty()),
        |owner| owner.capture(pointer),
        |owner| {
            let client = posix_client().map_err(map_posix_client_error)?;
            let prepared = client
                .prepare_shared_memory_open(wire::Open {
                    options,
                    mode: if options & wire::CREATE != 0 { mode } else { 0 },
                    name: &owner.name[..owner.length],
                })
                .map_err(map_posix_client_error)?;
            let limit = process_fd_limit()?;
            {
                let _native = defer_native_delivery();
                owner.reservation = Some(PendingFdReservation(
                    state().fds.reserve_from(0, limit).map_err(|_| EMFILE)?,
                ));
            }
            let opened = owner
                .execute(&prepared, client.transport().endpoint())?
                .ok_or(EIO)?;
            let _native = defer_native_delivery();
            let entry = object_entry(
                u64::from(opened.handle),
                opened.rights,
                FdKind::ObjectSharedMemory,
                (flags & 3) | O_CLOEXEC,
            );
            let fd = state()
                .fds
                .commit_reservation(&owner.reservation.as_ref().unwrap().0, entry)
                .map_err(|_| EIO)?;
            // No callback can occur between the successful commit and disarming
            // receive ownership. The FD, not the reply scope, now owns the Handle.
            owner.reply.disarm();
            Ok(fd)
        },
    )
}

pub(super) fn unlink(pointer: *const c_char) -> Result<c_int, c_int> {
    io_resources::with_initialized(
        || Ok(Resources::empty()),
        |owner| owner.capture(pointer),
        |owner| {
            let client = posix_client().map_err(map_posix_client_error)?;
            let prepared = client
                .prepare_shared_memory_unlink(&owner.name[..owner.length])
                .map_err(map_posix_client_error)?;
            owner.execute(&prepared, client.transport().endpoint())?;
            Ok(0)
        },
    )
}
