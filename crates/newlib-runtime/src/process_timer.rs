//! POSIX timer C boundary. Only local notification cookies enter IPC; C
//! records are imported/exported using checked copies, never raw references.
//! Signal/default notifications use the joint service signal dispatcher.
//! Thread callbacks and pthread attributes stay in the local callback registry.
//! Rollback retries are bounded and fair; persistent failures retain IDs until
//! a later API boundary or the service's process-exit cleanup. No RPC in Drop.
use super::*;
use mochios_posix_client::timer_value::{Error as ValueError, Token};
use posix_protocol::process_timer::{Clock, Notification, Value};

#[repr(C)]
pub(super) struct Itimerspec {
    interval: Timespec,
    value: Timespec,
}

#[derive(Clone, Copy)]
enum Cleanup {
    Free,
    Reserved,
    Pending(u64),
    Retrying,
}

// Reserve rollback capacity before creating any remote object. Failed deletion
// stays tracked, even when the application's output mapping was invalid.
pub(super) struct CleanupBook {
    slots: [Cleanup; 128],
    cursor: usize,
}
impl CleanupBook {
    pub(super) const fn new() -> Self {
        Self {
            slots: [Cleanup::Free; 128],
            cursor: 0,
        }
    }
    fn reserve(&mut self) -> Result<usize, c_int> {
        let index = self
            .slots
            .iter()
            .position(|slot| matches!(slot, Cleanup::Free))
            .ok_or(EAGAIN)?;
        self.slots[index] = Cleanup::Reserved;
        Ok(index)
    }
}

fn retry_cleanup() {
    let next = {
        let mut state = state();
        let book = &mut state.timer_cleanup;
        let next = (0..book.slots.len()).find_map(|offset| {
            let index = (book.cursor + offset) % book.slots.len();
            if let Cleanup::Pending(id) = book.slots[index] {
                Some((index, id))
            } else {
                None
            }
        });
        if let Some((index, _)) = next {
            book.slots[index] = Cleanup::Retrying;
            book.cursor = (index + 1) % book.slots.len();
        }
        next
    };
    let Some((index, id)) = next else { return };
    // No runtime lock is held during IPC. EINVAL is authoritative absence;
    // transport and other errors must retain the object for another attempt.
    let result = posix_client()
        .map_err(map_posix_client_error)
        .and_then(|client| client.timer_delete(id).map_err(map_posix_client_error));
    state().timer_cleanup.slots[index] = match result {
        Ok(()) | Err(EINVAL) => Cleanup::Free,
        Err(_) => Cleanup::Pending(id),
    };
}

struct Creation {
    slot: usize,
    token: Option<Token>,
    callback: Option<Token>,
    id: Option<u64>,
    bound: bool,
    committed: bool,
}
impl Creation {
    fn new() -> Result<Self, c_int> {
        Ok(Self {
            slot: state().timer_cleanup.reserve()?,
            token: None,
            callback: None,
            id: None,
            bound: false,
            committed: false,
        })
    }
}
impl Drop for Creation {
    fn drop(&mut self) {
        let mut state = state();
        if !self.committed {
            if self.bound {
                state.timer_values.retire(self.id.unwrap());
                state.timer_callbacks.values.retire(self.id.unwrap());
            } else if let Some(token) = self.token {
                let _ = state.timer_values.cancel(token);
            }
            if !self.bound {
                if let Some(token) = self.callback {
                    let _ = state.timer_callbacks.values.cancel(token);
                }
            }
        }
        state.timer_cleanup.slots[self.slot] = if self.committed {
            Cleanup::Free
        } else {
            self.id.map_or(Cleanup::Free, Cleanup::Pending)
        };
    }
}

fn value_error(error: ValueError) -> c_int {
    match error {
        ValueError::Full => EAGAIN,
        ValueError::Exhausted => EOVERFLOW,
        _ => EIO,
    }
}

fn clock(id: u64) -> Result<Clock, c_int> {
    if mochios_posix_client::process_clock::target(id).is_some() {
        return Ok(Clock::ProcessCpu);
    }
    if thread_clock::is_id(id) {
        return thread_clock::timer_source(id);
    }
    // newlib clockid_t is unsigned long. Do not truncate before validation,
    // or accidentally interpret Linux's clock numbers as the newlib ABI.
    match id {
        1 => Ok(Clock::Realtime),
        2 => Ok(Clock::ProcessCpu),
        4 => Ok(Clock::Monotonic),
        3 => Ok(Clock::ThreadCpu),
        _ => Err(EINVAL),
    }
}

fn notification(
    event: *const c_void,
) -> Result<
    (
        Notification,
        Option<usize>,
        bool,
        Option<timer_callbacks::Callback>,
    ),
    c_int,
> {
    if event.is_null() {
        // Default sigval is the final timer ID, installed before publication.
        return Ok((
            Notification::Signal {
                signal: 14,
                value: 0,
            },
            Some(0),
            true,
            None,
        ));
    }
    // SIGEV_THREAD's optional tail is deliberately not read for other modes.
    let mut bytes = [0; 16];
    user_copy::read(event.cast(), &mut bytes)?;
    let kind = c_int::from_ne_bytes(bytes[..4].try_into().unwrap());
    match kind {
        1 => Ok((Notification::None, None, false, None)),
        2 => {
            let signal = c_int::from_ne_bytes(bytes[4..8].try_into().unwrap());
            if !(1..=64).contains(&signal) {
                return Err(EINVAL);
            }
            let value = usize::from_ne_bytes(bytes[8..16].try_into().unwrap());
            Ok((
                Notification::Signal {
                    signal: signal as u32,
                    value: 0,
                },
                Some(value),
                false,
                None,
            ))
        }
        3 => {
            let value = usize::from_ne_bytes(bytes[8..16].try_into().unwrap());
            Ok((
                Notification::Thread { cookie: 1 },
                None,
                false,
                Some(timer_callbacks::import(event, value)?),
            ))
        }
        _ => Err(EINVAL),
    }
}

fn import(source: *const Itimerspec) -> Result<Value, c_int> {
    let mut bytes = [0; core::mem::size_of::<Itimerspec>()];
    user_copy::read(source.cast(), &mut bytes)?;
    let time = |base| {
        let field = |offset| {
            i64::from_ne_bytes(bytes[base + offset..base + offset + 8].try_into().unwrap())
        };
        let seconds = field(core::mem::offset_of!(Timespec, tv_sec));
        let nanos = field(core::mem::offset_of!(Timespec, tv_nsec));
        if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
            return Err(EINVAL);
        }
        Ok(seconds as u128 * 1_000_000_000 + nanos as u128)
    };
    Ok(Value {
        interval_ns: time(core::mem::offset_of!(Itimerspec, interval))?,
        remaining_ns: time(core::mem::offset_of!(Itimerspec, value))?,
    })
}

fn export(destination: *mut Itimerspec, value: Value) -> Result<(), c_int> {
    let mut bytes = [0; core::mem::size_of::<Itimerspec>()];
    for (base, nanos) in [
        (
            core::mem::offset_of!(Itimerspec, interval),
            value.interval_ns,
        ),
        (core::mem::offset_of!(Itimerspec, value), value.remaining_ns),
    ] {
        let seconds = i64::try_from(nanos / 1_000_000_000).map_err(|_| EOVERFLOW)?;
        for (offset, value) in [
            (core::mem::offset_of!(Timespec, tv_sec), seconds),
            (
                core::mem::offset_of!(Timespec, tv_nsec),
                (nanos % 1_000_000_000) as i64,
            ),
        ] {
            bytes[base + offset..base + offset + 8].copy_from_slice(&value.to_ne_bytes());
        }
    }
    user_copy::write(destination.cast(), &bytes)
}

fn guarded(operation: impl FnOnce() -> Result<c_int, c_int>) -> c_int {
    let result = (|| {
        let (_, control) = register_current_thread().ok_or(EAGAIN)?;
        let _delivery =
            mochios_posix_client::upcall_guard::Guard::enter(&control.native_delivery_defer)
                .ok_or(EOVERFLOW)?;
        retry_cleanup();
        let result = operation();
        retry_cleanup();
        result
    })();
    result_with_errno(result, -1)
}

#[unsafe(no_mangle)]
pub extern "C" fn timer_create(clock_id: u64, event: *const c_void, output: *mut usize) -> c_int {
    guarded(|| {
        let clock = clock(clock_id)?;
        if output.is_null() {
            return Err(EFAULT);
        }
        let (mut notification, value, default, callback) = notification(event)?;
        let mut creation = Creation::new()?;
        let target = if thread_clock::is_id(clock_id) {
            Some(thread_clock::timer_target(clock_id)?)
        } else {
            None
        };
        if let Some(callback) = callback {
            timer_callbacks::ensure_dispatcher()?;
            let owner = if clock == Clock::ThreadCpu {
                let (_, control) = current_thread_control().ok_or(EAGAIN)?;
                Some(target.as_ref().map_or_else(
                    || control.native_id.load(Ordering::Acquire),
                    |(_, native)| *native,
                ))
            } else {
                None
            };
            let token = timer_callbacks::reserve(callback, owner, clock_id)?;
            creation.callback = Some(token);
            notification = Notification::Thread {
                cookie: token.raw(),
            };
        }
        if let Some(value) = value {
            let token = if clock == Clock::ThreadCpu {
                let (_, control) = current_thread_control().ok_or(EAGAIN)?;
                let mut state = state();
                if let Some((_, native)) = &target {
                    if !state
                        .thread_clocks
                        .resolve(clock_id)
                        .is_some_and(|target| target.native_thread == *native)
                    {
                        return Err(EINVAL);
                    }
                }
                state.timer_values.reserve_owned(
                    value,
                    target.as_ref().map_or_else(
                        || control.native_id.load(Ordering::Acquire),
                        |(_, native)| *native,
                    ),
                )
            } else {
                state().timer_values.reserve(value)
            }
            .map_err(value_error)?;
            creation.token = Some(token);
            if let Notification::Signal { value, .. } = &mut notification {
                *value = token.raw()
            }
        }
        let client = posix_client().map_err(map_posix_client_error)?;
        let id = match &target {
            Some((reference, _)) => {
                client.timer_create_for_thread(reference.handle(), notification)
            }
            None => match mochios_posix_client::process_clock::target(clock_id) {
                Some(pid) => client.timer_create_for_process(pid, notification),
                None => client.timer_create(clock, notification),
            },
        }
        .map_err(map_posix_client_error)?;
        creation.id = Some(id);
        // Release the native reference and its fork/callback guard before
        // touching application output. A fault may escape this C entry point.
        drop(target);
        if let Some(token) = creation.token {
            let mut state = state();
            if default {
                state
                    .timer_values
                    .update_reserved(token, id as usize)
                    .map_err(value_error)?
            }
            state.timer_values.bind(token, id).map_err(value_error)?;
            creation.bound = true;
        }
        if let Some(token) = creation.callback {
            state()
                .timer_callbacks
                .values
                .bind(token, id)
                .map_err(value_error)?;
            creation.bound = true;
        }
        user_copy::write(output.cast(), &(id as usize).to_ne_bytes())?;
        creation.committed = true;
        Ok(0)
    })
}

/// No RPC or application callback during final native-thread retirement.
/// The service retires the corresponding timer after observing native exit.
pub(super) fn thread_exit(owner: u64, publish_exit: impl FnOnce()) {
    let mut state = state();
    state.timer_values.retire_owner(owner);
    state.timer_callbacks.values.retire_owner(owner);
    state.thread_clocks.retire_native(owner);
    // Exclude new clock/value registration until the exited state is visible.
    // Otherwise a foreign timer could reserve a token after final retirement.
    publish_exit();
}

#[unsafe(no_mangle)]
pub extern "C" fn timer_delete(id: usize) -> c_int {
    guarded(|| {
        let result = posix_client()
            .map_err(map_posix_client_error)?
            .timer_delete(id as u64)
            .map_err(map_posix_client_error);
        if matches!(result, Ok(()) | Err(EINVAL)) {
            state().timer_values.retire(id as u64);
            state().timer_callbacks.values.retire(id as u64);
        }
        result.map(|()| 0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn timer_gettime(id: usize, output: *mut Itimerspec) -> c_int {
    guarded(|| {
        if output.is_null() {
            return Err(EFAULT);
        }
        let value = posix_client()
            .map_err(map_posix_client_error)?
            .timer_value(id as u64)
            .map_err(map_posix_client_error)?;
        export(output, value)?;
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn timer_settime(
    id: usize,
    flags: c_int,
    replacement: *const Itimerspec,
    previous: *mut Itimerspec,
) -> c_int {
    guarded(|| {
        if flags & !4 != 0 {
            return Err(EINVAL);
        }
        // Import before an aliased output, and keep full i64 timespec range.
        let value = import(replacement)?;
        let old = posix_client()
            .map_err(map_posix_client_error)?
            .timer_set(id as u64, flags == 4, value)
            .map_err(map_posix_client_error)?;
        if !previous.is_null() {
            export(previous, old)?
        }
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn timer_getoverrun(id: usize) -> c_int {
    guarded(|| {
        let overrun = posix_client()
            .map_err(map_posix_client_error)?
            .timer_overrun(id as u64)
            .map_err(map_posix_client_error)?;
        c_int::try_from(overrun).map_err(|_| EOVERFLOW)
    })
}
