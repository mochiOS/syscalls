//! Process-local SIGEV_THREAD state. No application pointer crosses IPC.
use super::*;
use mochios_posix_client::timer_value::{Registry, Token};
use posix_protocol::timer_callback::Event;

#[derive(Clone, Copy)]
pub(super) struct Callback {
    function: usize,
    value: usize,
    attributes: PthreadAttr,
}

pub(super) struct Book {
    pub(super) values: Registry<Callback, 128>,
    jobs: [Option<Event>; 128],
}
impl Book {
    pub(super) const fn new() -> Self {
        Self {
            values: Registry::new(),
            jobs: [None; 128],
        }
    }
    pub(super) fn clear_for_fork(&mut self) {
        self.values.clear_for_fork();
        self.jobs.fill(None);
    }
}

fn attributes() -> PthreadAttr {
    PthreadAttr {
        is_initialized: 1,
        detachstate: PTHREAD_CREATE_DETACHED,
        stackaddr: ptr::null_mut(),
        stacksize: PTHREAD_DEFAULT_STACK_SIZE,
        guardsize: PAGE_SIZE,
        reserved: [0; 2],
    }
}

/// Copy only the SIGEV_THREAD tail. Other notification modes do not read it.
pub(super) fn import(event: *const c_void, value: usize) -> Result<Callback, c_int> {
    let mut tail = [0; 16];
    let address = (event as usize).checked_add(16).ok_or(EFAULT)?;
    user_copy::read(address as *const u8, &mut tail)?;
    let function = usize::from_ne_bytes(tail[..8].try_into().unwrap());
    if function == 0 {
        return Err(EINVAL);
    }
    let source = usize::from_ne_bytes(tail[8..].try_into().unwrap());
    let mut attr = attributes();
    if source != 0 {
        // Import bytes rather than dereferencing the application's opaque
        // pthread_attr_t. This matches the runtime's 40-byte storage ABI.
        let mut bytes = [0; 40];
        user_copy::read(source as *const u8, &mut bytes)?;
        let word = |offset| usize::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
        let initialized = c_int::from_ne_bytes(bytes[..4].try_into().unwrap());
        let detach = c_int::from_ne_bytes(bytes[4..8].try_into().unwrap());
        // pthread_attr_setinheritsched stores INHERIT / EXPLICIT as 0 / 1
        // in the first trailing word. The second word remains reserved.
        let inherit = u32::from_ne_bytes(bytes[32..36].try_into().unwrap());
        if initialized == 0
            || !matches!(detach, PTHREAD_CREATE_JOINABLE | PTHREAD_CREATE_DETACHED)
            || word(16) < PTHREAD_STACK_MIN
            || inherit > 1
            || bytes[36..] != [0; 4]
        {
            return Err(EINVAL);
        }
        attr.stackaddr = word(8) as *mut c_void;
        attr.stacksize = word(16);
        attr.guardsize = word(24);
        attr.reserved[0] = inherit;
        // A notification has no join owner. POSIX leaves joinable attributes
        // unspecified; all callbacks use the detached lifetime here.
    }
    Ok(Callback {
        function,
        value,
        attributes: attr,
    })
}

// OFF / starting / ready. One receiver per process, created only on demand.
static DISPATCHER: AtomicU32 = AtomicU32::new(0);
static RECEIVER: AtomicU32 = AtomicU32::new(0);
pub(super) fn reset_dispatcher_for_fork() {
    DISPATCHER.store(0, Ordering::Release);
    RECEIVER.store(0, Ordering::Release);
}

/// An implementation receiver is not an application thread which keeps a
/// POSIX process alive after its last pthread exits. Freeze native-thread
/// admission while counting, so callback creation cannot race the decision.
pub(super) fn finish_if_last_application() {
    let token = RECEIVER.load(Ordering::Acquire);
    if token == 0 {
        return;
    }
    let _capture = loop {
        match thread_lifecycle::capture() {
            Ok(capture) => break capture,
            Err(_) => {
                let _ = syscall::raw_syscall0(syscall::SyscallNumber::ThreadYield);
            }
        }
    };
    let Some(receiver) = thread_control(token) else {
        return;
    };
    if !THREADS.iter().any(|control| {
        !ptr::eq(control, receiver)
            && matches!(
                control.state.load(Ordering::Acquire),
                THREAD_STARTING | THREAD_RUNNING
            )
    }) {
        process_exit(0);
    }
}

pub(super) fn ensure_dispatcher() -> Result<(), c_int> {
    loop {
        match DISPATCHER.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => break,
            Err(2) => return Ok(()),
            Err(_) => native_mutex_wait(&DISPATCHER, 1),
        }
    }
    let attr = attributes();
    let mut thread = 0;
    // SAFETY: these are runtime-owned storage and a fixed entry point.
    let error = unsafe { pthread_create(&mut thread, &attr, Some(dispatch), ptr::null_mut()) };
    if error != 0 {
        DISPATCHER.store(0, Ordering::Release);
        native_mutex_wake_all(&DISPATCHER);
        return Err(error);
    }
    while DISPATCHER.load(Ordering::Acquire) == 1 {
        native_mutex_wait(&DISPATCHER, 1);
    }
    if DISPATCHER.load(Ordering::Acquire) == 2 {
        Ok(())
    } else {
        Err(EAGAIN)
    }
}

fn pause() {
    // Cancellation is disabled in the internal receiver, and its signals are
    // masked. Back off after resource or service failures without spinning.
    let delay = Timespec {
        tv_sec: 0,
        tv_nsec: 10_000_000,
    };
    unsafe { nanosleep(&delay, ptr::null_mut()) };
}

unsafe extern "C" fn dispatch(_: *mut c_void) -> *mut c_void {
    let initialized = (|| {
        let (token, control) = register_current_thread().ok_or(EAGAIN)?;
        let error =
            unsafe { pthread_setcancelstate(PTHREAD_CANCEL_DISABLE as c_int, ptr::null_mut()) };
        if error != 0 {
            return Err(error);
        }
        service_signal_mask(control, posix_protocol::SIGNAL_MASK_BLOCK, u64::MAX)?;
        RECEIVER.store(token, Ordering::Release);
        Ok::<(), c_int>(())
    })();
    DISPATCHER.store(if initialized.is_ok() { 2 } else { 0 }, Ordering::Release);
    native_mutex_wake_all(&DISPATCHER);
    if initialized.is_err() {
        return ptr::null_mut();
    }
    loop {
        let event = posix_client()
            .map_err(map_posix_client_error)
            .and_then(|client| client.timer_wait_callback().map_err(map_posix_client_error));
        match event {
            Ok(event) => {
                while launch(event).is_err() {
                    pause();
                }
            }
            Err(_) => pause(),
        }
    }
}

pub(super) fn launch(event: Event) -> Result<(), c_int> {
    let (index, callback) = {
        let mut state = state();
        let book = &mut state.timer_callbacks;
        let Ok(callback) = book.values.resolve(event.timer, event.cookie) else {
            // Deleted, failed creation, or otherwise invalid local cookie.
            return Ok(());
        };
        let index = book.jobs.iter().position(Option::is_none).ok_or(EAGAIN)?;
        book.jobs[index] = Some(event);
        (index, callback)
    };
    let mut thread = 0;
    // A slot owns no application allocation; a successful child takes it
    // before invoking C. Failed creation never leaves a queued job behind.
    let error = unsafe {
        pthread_create(
            &mut thread,
            &callback.attributes,
            Some(invoke),
            (index + 1) as *mut c_void,
        )
    };
    if error == 0 {
        return Ok(());
    }
    state().timer_callbacks.jobs[index] = None;
    Err(error)
}

pub(super) unsafe extern "C" fn invoke(argument: *mut c_void) -> *mut c_void {
    let callback = {
        let mut state = state();
        let book = &mut state.timer_callbacks;
        let Some(slot) = (argument as usize)
            .checked_sub(1)
            .and_then(|index| book.jobs.get_mut(index))
        else {
            return ptr::null_mut();
        };
        slot.take()
            .and_then(|event| book.values.resolve(event.timer, event.cookie).ok())
    };
    if let Some(callback) = callback {
        // SAFETY: SIGEV_THREAD supplies a C void(union sigval) callback. On
        // this ABI the eight-byte union is passed in the integer register.
        // No lock, slot, Handle, or heap owner remains across application C.
        let function: unsafe extern "C" fn(usize) =
            unsafe { core::mem::transmute(callback.function) };
        unsafe { function(callback.value) };
    }
    ptr::null_mut()
}

pub(super) fn reserve(callback: Callback, owner: Option<u64>, clock: u64) -> Result<Token, c_int> {
    let mut state = state();
    if thread_clock::is_id(clock)
        && !state
            .thread_clocks
            .resolve(clock)
            .is_some_and(|target| Some(target.native_thread) == owner)
    {
        return Err(EINVAL);
    }
    let values = &mut state.timer_callbacks.values;
    match owner {
        None => values.reserve(callback),
        Some(owner) => values.reserve_owned(callback, owner),
    }
    .map_err(|error| match error {
        mochios_posix_client::timer_value::Error::Full => EAGAIN,
        mochios_posix_client::timer_value::Error::Exhausted => EOVERFLOW,
        _ => EINVAL,
    })
}
