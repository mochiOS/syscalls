//! Attribute APIs for the currently supported normal scheduling class.
//! Do not advertise POSIX priority scheduling: realtime dispatch and
//! process-local contention are not implemented by the native scheduler.
use super::{EINVAL, ENOTSUP, PthreadAttr, SchedParam, c_int, c_void};

const SCOPE_PROCESS: c_int = 0;
const SCOPE_SYSTEM: c_int = 1;
const INHERIT_SCHED: c_int = 1;
const EXPLICIT_SCHED: c_int = 2;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getstackaddr(
    attr: *const PthreadAttr,
    address: *mut *mut c_void,
) -> c_int {
    if attr.is_null() || address.is_null() || unsafe { (*attr).is_initialized } == 0 {
        return EINVAL;
    }
    unsafe { address.write((*attr).stackaddr) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setstackaddr(
    attr: *mut PthreadAttr,
    address: *mut c_void,
) -> c_int {
    if attr.is_null() || address.is_null() || unsafe { (*attr).is_initialized } == 0 {
        return EINVAL;
    }
    unsafe { (*attr).stackaddr = address };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getscope(
    attr: *const PthreadAttr,
    scope: *mut c_int,
) -> c_int {
    if attr.is_null() || scope.is_null() || unsafe { (*attr).is_initialized } == 0 {
        return EINVAL;
    }
    unsafe { scope.write(SCOPE_SYSTEM) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setscope(attr: *mut PthreadAttr, scope: c_int) -> c_int {
    if attr.is_null() || unsafe { (*attr).is_initialized } == 0 {
        return EINVAL;
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
    if attr.is_null() || inherit.is_null() || unsafe { (*attr).is_initialized } == 0 {
        return EINVAL;
    }
    let value = if unsafe { (*attr).reserved[0] } == 0 {
        INHERIT_SCHED
    } else {
        EXPLICIT_SCHED
    };
    unsafe { inherit.write(value) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setinheritsched(
    attr: *mut PthreadAttr,
    inherit: c_int,
) -> c_int {
    if attr.is_null() || unsafe { (*attr).is_initialized } == 0 {
        return EINVAL;
    }
    let value = match inherit {
        INHERIT_SCHED => 0,
        EXPLICIT_SCHED => 1,
        _ => return EINVAL,
    };
    // Both choices currently resolve to OTHER/priority zero: no native thread
    // can acquire a realtime class through these attributes.
    unsafe { (*attr).reserved[0] = value };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getschedpolicy(
    attr: *const PthreadAttr,
    policy: *mut c_int,
) -> c_int {
    if attr.is_null() || policy.is_null() || unsafe { (*attr).is_initialized } == 0 {
        return EINVAL;
    }
    unsafe { policy.write(0) }; // newlib SCHED_OTHER
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setschedpolicy(
    attr: *mut PthreadAttr,
    policy: c_int,
) -> c_int {
    if attr.is_null() || unsafe { (*attr).is_initialized } == 0 {
        return EINVAL;
    }
    match policy {
        0 => 0,
        1 | 2 => ENOTSUP, // FIFO / RR require native scheduling mechanisms.
        _ => EINVAL,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_getschedparam(
    attr: *const PthreadAttr,
    parameter: *mut SchedParam,
) -> c_int {
    if attr.is_null() || parameter.is_null() || unsafe { (*attr).is_initialized } == 0 {
        return EINVAL;
    }
    unsafe { parameter.write(SchedParam { sched_priority: 0 }) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pthread_attr_setschedparam(
    attr: *mut PthreadAttr,
    parameter: *const SchedParam,
) -> c_int {
    if attr.is_null() || parameter.is_null() || unsafe { (*attr).is_initialized } == 0 {
        return EINVAL;
    }
    if unsafe { (*parameter).sched_priority } != 0 {
        return EINVAL;
    }
    0
}
