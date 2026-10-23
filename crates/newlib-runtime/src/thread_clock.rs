//! pthread CPU clocks stay process-local. Every sample uses a pinned native
//! Thread Handle and verifies its full identity before reading its CPU clock.
use super::*;
use mochios_posix_client::thread_clock::{Error, Target};

pub(super) fn is_id(id: u64) -> bool {
    id >= mochios_posix_client::thread_clock::FIRST_ID
}

fn live(target: Target) -> bool {
    thread_control(target.thread).is_some_and(|control| {
        matches!(
            control.state.load(Ordering::Acquire),
            THREAD_STARTING | THREAD_RUNNING
        ) && control.native_id.load(Ordering::Acquire) == target.native_thread
    })
}

fn status(reference: &thread_reference::Reference) -> Result<syscall::ThreadStatus, c_int> {
    let mut value = syscall::ThreadStatus::default();
    syscall::raw_syscall2(
        syscall::SyscallNumber::ThreadHandleStatus,
        u64::from(reference.handle()),
        (&mut value as *mut syscall::ThreadStatus) as u64,
    )
    .into_result()
    .map_err(|error| {
        if error.native_error() == Some(mnu_abi::status::Error::NotFound) {
            ESRCH
        } else {
            map_kernel_errno(error.raw())
        }
    })?;
    if value.thread_id == 0
        || value.process_id == 0
        || value.reserved != 0
        || !(mnu_abi::THREAD_STATE_READY..=mnu_abi::THREAD_STATE_TERMINATED).contains(&value.state)
    {
        return Err(EIO);
    }
    if value.state == mnu_abi::THREAD_STATE_TERMINATED {
        return Err(ESRCH);
    }
    Ok(value)
}

fn target(id: u64) -> Result<Target, c_int> {
    let target = state().thread_clocks.resolve(id).ok_or(EINVAL)?;
    if !live(target) {
        return Err(EINVAL);
    }
    Ok(target)
}

fn reference_with_rights(
    target: Target,
    rights: u64,
) -> Result<thread_reference::Reference, c_int> {
    let reference = thread_reference::snapshot(target.thread, rights)
        .map_err(|error| if error == ESRCH { EINVAL } else { error })?;
    let identity =
        status(&reference).map_err(|error| if error == ESRCH { EINVAL } else { error })?;
    if identity.thread_id != target.native_thread {
        return Err(EINVAL);
    }
    Ok(reference)
}

fn reference(target: Target) -> Result<thread_reference::Reference, c_int> {
    reference_with_rights(target, syscall::HANDLE_RIGHT_WAIT)
}

#[unsafe(no_mangle)]
pub extern "C" fn pthread_getcpuclockid(thread: Pthread, output: *mut u64) -> c_int {
    let result = (|| {
        if output.is_null() {
            return Err(EFAULT);
        }
        let (current, _) = register_current_thread().ok_or(EAGAIN)?;
        loop {
            let control = thread_control(thread).ok_or(ESRCH)?;
            let state = control.state.load(Ordering::Acquire);
            if state == THREAD_STARTING && current != thread {
                native_mutex_wait(&control.state, state);
                continue;
            }
            break;
        }
        let id = {
            let reference = thread_reference::snapshot(thread, syscall::HANDLE_RIGHT_WAIT)?;
            let identity = status(&reference)?;
            syscall::execution::thread_clock(reference.handle()).map_err(|error| {
                if error.native_error() == Some(mnu_abi::status::Error::NotFound) {
                    ESRCH
                } else {
                    map_kernel_errno(error.raw())
                }
            })?;
            let target = Target {
                thread,
                native_thread: identity.thread_id,
            };
            let mut state = state();
            state.thread_clocks.retain(live);
            if !live(target) {
                return Err(ESRCH);
            }
            state
                .thread_clocks
                .get_or_insert(target)
                .map_err(|error| match error {
                    Error::Full => EAGAIN,
                    Error::Exhausted => EOVERFLOW,
                    Error::InvalidTarget => EINVAL,
                })?
        };
        // No owned reference or runtime lock remains across an application
        // output fault, handler escape or cancellation triggered by that fault.
        user_copy::write(output.cast(), &id.to_ne_bytes())?;
        Ok(())
    })();
    result.err().unwrap_or(0)
}

pub(super) fn read(id: u64, output: *mut Timespec) -> Result<c_int, c_int> {
    let value = {
        let reference = reference(target(id)?)?;
        syscall::execution::thread_clock(reference.handle()).map_err(|error| {
            if error.native_error() == Some(mnu_abi::status::Error::NotFound) {
                EINVAL
            } else {
                map_kernel_errno(error.raw())
            }
        })?
    };
    let seconds = i64::try_from(value.seconds).map_err(|_| EOVERFLOW)?;
    time_memory::write_timespec(
        output,
        Timespec {
            tv_sec: seconds,
            tv_nsec: i64::from(value.nanoseconds),
        },
    )?;
    Ok(0)
}

pub(super) fn resolution(id: u64, output: *mut Timespec) -> Result<c_int, c_int> {
    let reference = reference(target(id)?)?;
    let mut info = mnu_abi::ClockInfo::default();
    syscall_errno(syscall::raw_syscall3(
        syscall::SyscallNumber::ClockDescribe,
        mnu_abi::ClockId::ThreadCpu as u64,
        (&mut info as *mut mnu_abi::ClockInfo) as u64,
        core::mem::size_of::<mnu_abi::ClockInfo>() as u64,
    ))?;
    drop(reference);
    let (tv_sec, tv_nsec) = mochios_posix_client::time::clock_resolution(info.quantum_nanoseconds)?;
    if !output.is_null() {
        time_memory::write_timespec(output, Timespec { tv_sec, tv_nsec })?;
    }
    Ok(0)
}

/// The local clock ID grants no authority. Pin and explicitly transfer a
/// rights-reduced reference to select its native thread during timer creation.
pub(super) fn timer_target(id: u64) -> Result<(thread_reference::Reference, u64), c_int> {
    let target = target(id)?;
    let reference = reference_with_rights(
        target,
        syscall::HANDLE_RIGHT_WAIT | syscall::HANDLE_RIGHT_TRANSFER,
    )?;
    Ok((reference, target.native_thread))
}

pub(super) fn timer_source(id: u64) -> Result<posix_protocol::process_timer::Clock, c_int> {
    target(id)?;
    Ok(posix_protocol::process_timer::Clock::ThreadCpu)
}
