//! Attribute APIs for the currently supported normal scheduling class.
//! Do not advertise POSIX priority scheduling: realtime dispatch and
//! process-local contention are not implemented by the native scheduler.
use super::{
    EINVAL, ENOTSUP, PAGE_SIZE, PTHREAD_CREATE_DETACHED, PTHREAD_CREATE_JOINABLE,
    PTHREAD_DEFAULT_STACK_SIZE, PTHREAD_STACK_MIN, PthreadAttr, SchedParam, c_int, c_void,
    user_copy,
};

fn address(attr: *const PthreadAttr, offset: usize, length: usize) -> Result<usize, c_int> {
    if attr.is_null() || offset.checked_add(length).ok_or(EINVAL)? > size_of::<PthreadAttr>() {
        return Err(EINVAL);
    }
    (attr as usize).checked_add(offset).ok_or(super::EFAULT)
}

fn load<const N: usize>(attr: *const PthreadAttr, offset: usize) -> Result<[u8; N], c_int> {
    let source = address(attr, offset, N)?;
    let mut bytes = [0; N];
    user_copy::read(source as *const u8, &mut bytes)?;
    Ok(bytes)
}

fn initialized(attr: *const PthreadAttr) -> Result<(), c_int> {
    if c_int::from_ne_bytes(load(
        attr,
        core::mem::offset_of!(PthreadAttr, is_initialized),
    )?) == 0
    {
        Err(EINVAL)
    } else {
        Ok(())
    }
}

pub(super) fn get<const N: usize>(
    attr: *const PthreadAttr,
    output: *mut u8,
    offset: usize,
) -> c_int {
    let result = (|| {
        if output.is_null() {
            return Err(EINVAL);
        }
        initialized(attr)?;
        // Snapshot before output, including when output aliases the attribute.
        let bytes = load::<N>(attr, offset)?;
        user_copy::write(output, &bytes)
    })();
    result.err().unwrap_or(0)
}

pub(super) fn set<const N: usize>(attr: *mut PthreadAttr, offset: usize, bytes: [u8; N]) -> c_int {
    let result = (|| {
        initialized(attr)?;
        let destination = address(attr, offset, N)?;
        user_copy::write(destination as *mut u8, &bytes)
    })();
    result.err().unwrap_or(0)
}

pub(super) fn init(attr: *mut PthreadAttr) -> c_int {
    let result = (|| {
        let destination = address(attr, 0, size_of::<PthreadAttr>())?;
        // Encode initialized bytes, never a Rust structure with padding.
        let mut bytes = [0; size_of::<PthreadAttr>()];
        macro_rules! field {
            ($name:ident, $value:expr) => {{
                let value = $value.to_ne_bytes();
                let offset = core::mem::offset_of!(PthreadAttr, $name);
                bytes[offset..offset + value.len()].copy_from_slice(&value);
            }};
        }
        field!(is_initialized, 1 as c_int);
        field!(detachstate, PTHREAD_CREATE_JOINABLE);
        field!(stacksize, PTHREAD_DEFAULT_STACK_SIZE);
        field!(guardsize, PAGE_SIZE);
        user_copy::write(destination as *mut u8, &bytes)
    })();
    result.err().unwrap_or(0)
}

pub(super) fn set_stack(attr: *mut PthreadAttr, stack: *mut c_void, length: usize) -> c_int {
    if stack.is_null() || length < PTHREAD_STACK_MIN {
        return EINVAL;
    }
    let mut bytes = [0; 2 * size_of::<usize>()];
    bytes[..size_of::<usize>()].copy_from_slice(&(stack as usize).to_ne_bytes());
    bytes[size_of::<usize>()..].copy_from_slice(&length.to_ne_bytes());
    set(attr, core::mem::offset_of!(PthreadAttr, stackaddr), bytes)
}

pub(super) fn get_stack(
    attr: *const PthreadAttr,
    stack: *mut *mut c_void,
    length: *mut usize,
) -> c_int {
    let result = (|| {
        if stack.is_null() || length.is_null() {
            return Err(EINVAL);
        }
        initialized(attr)?;
        let bytes = load::<{ 2 * size_of::<usize>() }>(
            attr,
            core::mem::offset_of!(PthreadAttr, stackaddr),
        )?;
        // Both inputs are captured before either potentially aliasing output.
        user_copy::write(stack.cast(), &bytes[..size_of::<usize>()])?;
        user_copy::write(length.cast(), &bytes[size_of::<usize>()..])
    })();
    result.err().unwrap_or(0)
}

/// Capture caller memory once, before pthread_create registers or allocates.
/// The pointer is never borrowed and cannot change later creation decisions.
pub(super) fn for_create(attr: *const PthreadAttr) -> Result<PthreadAttr, c_int> {
    if attr.is_null() {
        return Ok(PthreadAttr {
            is_initialized: 1,
            detachstate: PTHREAD_CREATE_JOINABLE,
            stackaddr: core::ptr::null_mut(),
            stacksize: PTHREAD_DEFAULT_STACK_SIZE,
            guardsize: PAGE_SIZE,
            reserved: [0; 2],
        });
    }
    let bytes = load::<{ size_of::<PthreadAttr>() }>(attr, 0)?;
    macro_rules! field {
        ($name:ident, $integer:ty) => {{
            let offset = core::mem::offset_of!(PthreadAttr, $name);
            <$integer>::from_ne_bytes(
                bytes[offset..offset + size_of::<$integer>()]
                    .try_into()
                    .unwrap(),
            )
        }};
    }
    let result = PthreadAttr {
        is_initialized: field!(is_initialized, c_int),
        detachstate: field!(detachstate, c_int),
        stackaddr: field!(stackaddr, usize) as *mut c_void,
        stacksize: field!(stacksize, usize),
        guardsize: field!(guardsize, usize),
        reserved: [0; 2],
    };
    if result.is_initialized == 0
        || !matches!(
            result.detachstate,
            PTHREAD_CREATE_DETACHED | PTHREAD_CREATE_JOINABLE
        )
        || result.stacksize < PTHREAD_STACK_MIN
    {
        Err(EINVAL)
    } else {
        Ok(result)
    }
}

const SCOPE_PROCESS: c_int = 0;
const SCOPE_SYSTEM: c_int = 1;
const INHERIT_SCHED: c_int = 1;
const EXPLICIT_SCHED: c_int = 2;

fn fixed<const N: usize>(attr: *const PthreadAttr, output: *mut u8, bytes: [u8; N]) -> c_int {
    let result = (|| {
        if output.is_null() {
            return Err(EINVAL);
        }
        initialized(attr)?;
        user_copy::write(output, &bytes)
    })();
    result.err().unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getstackaddr(
    attr: *const PthreadAttr,
    address: *mut *mut c_void,
) -> c_int {
    get::<{ size_of::<usize>() }>(
        attr,
        address.cast(),
        core::mem::offset_of!(PthreadAttr, stackaddr),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setstackaddr(
    attr: *mut PthreadAttr,
    address: *mut c_void,
) -> c_int {
    if address.is_null() {
        return EINVAL;
    }
    set(
        attr,
        core::mem::offset_of!(PthreadAttr, stackaddr),
        (address as usize).to_ne_bytes(),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getscope(
    attr: *const PthreadAttr,
    scope: *mut c_int,
) -> c_int {
    fixed(attr, scope.cast(), SCOPE_SYSTEM.to_ne_bytes())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setscope(attr: *mut PthreadAttr, scope: c_int) -> c_int {
    if let Err(error) = initialized(attr) {
        return error;
    }
    match scope {
        SCOPE_SYSTEM => 0,
        SCOPE_PROCESS => ENOTSUP,
        _ => EINVAL,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getinheritsched(
    attr: *const PthreadAttr,
    inherit: *mut c_int,
) -> c_int {
    let result = (|| {
        if inherit.is_null() {
            return Err(EINVAL);
        }
        initialized(attr)?;
        let explicit =
            u32::from_ne_bytes(load(attr, core::mem::offset_of!(PthreadAttr, reserved))?);
        let value = if explicit == 0 {
            INHERIT_SCHED
        } else {
            EXPLICIT_SCHED
        };
        user_copy::write(inherit.cast(), &value.to_ne_bytes())
    })();
    result.err().unwrap_or(0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setinheritsched(
    attr: *mut PthreadAttr,
    inherit: c_int,
) -> c_int {
    let value: u32 = match inherit {
        INHERIT_SCHED => 0,
        EXPLICIT_SCHED => 1,
        _ => return EINVAL,
    };
    set(
        attr,
        core::mem::offset_of!(PthreadAttr, reserved),
        value.to_ne_bytes(),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getschedpolicy(
    attr: *const PthreadAttr,
    policy: *mut c_int,
) -> c_int {
    fixed(attr, policy.cast(), (0 as c_int).to_ne_bytes())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setschedpolicy(
    attr: *mut PthreadAttr,
    policy: c_int,
) -> c_int {
    if let Err(error) = initialized(attr) {
        return error;
    }
    match policy {
        0 => 0,
        1 | 2 => ENOTSUP,
        _ => EINVAL,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getschedparam(
    attr: *const PthreadAttr,
    parameter: *mut SchedParam,
) -> c_int {
    fixed(attr, parameter.cast(), (0 as c_int).to_ne_bytes())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setschedparam(
    attr: *mut PthreadAttr,
    parameter: *const SchedParam,
) -> c_int {
    let result = (|| {
        if parameter.is_null() {
            return Err(EINVAL);
        }
        initialized(attr)?;
        let mut bytes = [0; size_of::<c_int>()];
        user_copy::read(parameter.cast(), &mut bytes)?;
        if c_int::from_ne_bytes(bytes) != 0 {
            return Err(EINVAL);
        }
        Ok(())
    })();
    result.err().unwrap_or(0)
}
