//! Local socket FDs own native Provider Handles. Pair installation is atomic;
//! descriptor flags stay local while status options are shared by the Provider.

use super::*;
use mochios_posix_protocol::socket as wire;

struct PendingPair([FdReservation; 2]);
impl Drop for PendingPair {
    fn drop(&mut self) {
        let mut state = state();
        for reservation in &self.0 {
            state.fds.cancel_reservation(reservation);
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn socketpair(
    domain: c_int,
    kind: c_int,
    protocol: c_int,
    output: *mut c_int,
) -> c_int {
    let result = (|| {
        if output.is_null() {
            return Err(EFAULT);
        }
        let (create, cloexec) = mochios_posix_client::socket::newlib_create(domain, kind, protocol)
            .map_err(|error| mochios_posix_client::newlib_errno::from_status(i64::from(error)))?;
        let limit = process_fd_limit()?;
        let pending = PendingPair(
            state()
                .fds
                .reserve_pair_from(0, limit)
                .map_err(|_| EMFILE)?,
        );
        let opened = posix_client()
            .map_err(map_posix_client_error)?
            .socket_pair(create, close_object_handle)
            .map_err(map_posix_client_error)?;
        let flags = 2 | if cloexec { O_CLOEXEC } else { 0 };
        let entries = opened.map(|opened| {
            object_entry(
                u64::from(opened.handle),
                opened.rights,
                FdKind::ObjectSocket,
                flags,
            )
        });
        let installed = state()
            .fds
            .commit_pair([&pending.0[0], &pending.0[1]], entries);
        match installed {
            Ok(fds) => {
                unsafe {
                    output.write(fds[0]);
                    output.add(1).write(fds[1]);
                }
                Ok(0)
            }
            Err(_) => {
                for opened in opened {
                    close_object_handle(opened.handle);
                }
                Err(EIO)
            }
        }
    })();
    result_with_errno(result, -1)
}

fn control(entry: FdEntry, tag: u64, input: &[u8], output: &mut [u8]) -> Result<(), c_int> {
    let count = syscall_errno(syscall::raw_syscall6(
        syscall::SyscallNumber::HandleControl,
        entry.handle.lower_handle,
        tag,
        input.as_ptr() as u64,
        input.len() as u64,
        output.as_mut_ptr() as u64,
        output.len() as u64,
    ))?;
    if count as usize != output.len() {
        return Err(EIO);
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub extern "C" fn shutdown(fd: c_int, how: c_int) -> c_int {
    let result = (|| {
        let entry = with_fd_entry(fd)?;
        if entry.handle.kind != FdKind::ObjectSocket {
            return Err(mochios_posix_client::newlib_errno::from_status(-88));
        }
        if !(0..=2).contains(&how) {
            return Err(EINVAL);
        }
        control(
            entry,
            wire::CONTROL_SHUTDOWN,
            &(how as u32).to_le_bytes(),
            &mut [],
        )?;
        Ok(0)
    })();
    result_with_errno(result, -1)
}

pub(super) fn get_status_flags(entry: FdEntry) -> Result<c_int, c_int> {
    let mut bytes = [0; 4];
    control(entry, wire::CONTROL_GET_OPTIONS, &[], &mut bytes)?;
    let options = u32::from_le_bytes(bytes);
    if options & !wire::NONBLOCKING != 0 {
        return Err(EIO);
    }
    Ok(2 | if options & wire::NONBLOCKING != 0 {
        O_NONBLOCK
    } else {
        0
    })
}

pub(super) fn set_status_flags(entry: FdEntry, flags: c_int) -> Result<(), c_int> {
    if flags & !(3 | O_NONBLOCK) != 0 {
        return Err(EINVAL);
    }
    let options: u32 = if flags & O_NONBLOCK != 0 {
        wire::NONBLOCKING
    } else {
        0
    };
    control(
        entry,
        wire::CONTROL_SET_OPTIONS,
        &options.to_le_bytes(),
        &mut [],
    )
}

pub(super) fn poll_events(entry: FdEntry, events: i16) -> Result<i16, c_int> {
    let mut bytes = [0; 4];
    control(entry, wire::CONTROL_READINESS, &[], &mut bytes)?;
    let bits = u32::from_le_bytes(bytes);
    if bits & !31 != 0 {
        return Err(EIO);
    }
    Ok(mochios_posix_client::socket::poll_events(bits, events))
}
