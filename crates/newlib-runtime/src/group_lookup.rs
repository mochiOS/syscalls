//! C group lookups backed by the delegated public account service.
use super::*;
use posix_protocol::public_group::{self as wire, Query, Record};
const MAX_BUFFER: usize = wire::MAX_RECORD + (wire::MAX_MEMBERS + 1) * 8 + 8;

#[repr(C)]
pub(super) struct Group {
    name: *mut c_char,
    password: *mut c_char,
    gid: groups::Gid,
    members: *mut *mut c_char,
}
const _: () = {
    assert!(core::mem::size_of::<Group>() == 32);
    assert!(core::mem::offset_of!(Group, gid) == 16);
    assert!(core::mem::offset_of!(Group, members) == 24);
};
#[repr(align(8))]
pub(super) struct Cache {
    record: [u8; 32],
    text: [u8; MAX_BUFFER],
}
impl Cache {
    pub const fn new() -> Self {
        Self {
            record: [0; 32],
            text: [0; MAX_BUFFER],
        }
    }
}

fn publish(
    record: Record<'_>,
    output: *mut Group,
    buffer: *mut c_char,
    length: usize,
    result: *mut *mut Group,
) -> Result<(), c_int> {
    let gid = groups::Gid::try_from(record.gid).map_err(|_| EOVERFLOW)?;
    let string_bytes = record.name.len()
        + 1
        + 2
        + record
            .members()
            .iter()
            .map(|name| name.len() + 1)
            .sum::<usize>();
    let base = buffer as usize;
    let table = base
        .checked_add(string_bytes)
        .and_then(|end| end.checked_add(7))
        .map(|end| end & !7)
        .ok_or(EFAULT)?;
    let offset = table.checked_sub(base).ok_or(EFAULT)?;
    let required = offset
        .checked_add((record.members().len() + 1) * 8)
        .ok_or(EOVERFLOW)?;
    if required > length {
        return Err(ERANGE);
    }
    if buffer.is_null() || output.is_null() || required > MAX_BUFFER {
        return Err(EFAULT);
    }
    base.checked_add(required).ok_or(EFAULT)?;
    let mut text = [0u8; MAX_BUFFER];
    text[..record.name.len()].copy_from_slice(record.name.as_bytes());
    let password = record.name.len() + 1;
    text[password] = b'x';
    let mut at = password + 2;
    for (index, name) in record.members().iter().enumerate() {
        text[offset + index * 8..offset + (index + 1) * 8]
            .copy_from_slice(&(base + at).to_ne_bytes());
        text[at..at + name.len()].copy_from_slice(name.as_bytes());
        at += name.len() + 1;
    }
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&base.to_ne_bytes());
    bytes[8..16].copy_from_slice(&(base + password).to_ne_bytes());
    bytes[16..18].copy_from_slice(&gid.to_ne_bytes());
    bytes[24..32].copy_from_slice(&table.to_ne_bytes());
    user_copy::write(buffer.cast(), &text[..required])?;
    user_copy::write(output.cast(), &bytes)?;
    user_copy::write(result.cast(), &(output as usize).to_ne_bytes())
}
fn fetch<'a>(
    query: Query<'_>,
    response: &'a mut [u8; wire::MAX_RECORD],
) -> Result<Option<Record<'a>>, c_int> {
    let client = posix_client().map_err(map_posix_client_error)?;
    let n = match client
        .lookup_group(query, response)
        .map_err(map_posix_client_error)
    {
        Ok(n) => n,
        Err(ENOENT) => return Ok(None),
        Err(error) => return Err(error),
    };
    wire::decode_record(&response[..n])
        .map(Some)
        .map_err(|_| EIO)
}
fn lookup(
    query: Query<'_>,
    output: *mut Group,
    buffer: *mut c_char,
    length: usize,
    result: *mut *mut Group,
) -> Result<(), c_int> {
    let mut response = [0; wire::MAX_RECORD];
    if let Some(record) = fetch(query, &mut response)? {
        publish(record, output, buffer, length, result)?;
    }
    Ok(())
}
fn named<T>(
    name: *const c_char,
    operation: impl FnOnce(Query<'_>) -> Result<T, c_int>,
    missing: T,
) -> Result<T, c_int> {
    let mut name_bytes = [0; wire::MAX_NAME];
    let n = match user_copy::capture_text(name, &mut name_bytes, ENOENT) {
        Ok(n) => n,
        Err(ENOENT) => return Ok(missing),
        Err(error) => return Err(error),
    };
    let name = match core::str::from_utf8(&name_bytes[..n]) {
        Ok(name)
            if !name.is_empty()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-')) =>
        {
            name
        }
        _ => return Ok(missing),
    };
    operation(Query::Name(name))
}
fn cached(query: Query<'_>) -> Result<*mut Group, c_int> {
    let mut response = [0; wire::MAX_RECORD];
    let Some(record) = fetch(query, &mut response)? else {
        return Ok(ptr::null_mut());
    };
    let mut state = STATE.lock();
    let cache = &mut state.group_cache;
    let output = cache.record.as_mut_ptr().cast();
    let mut result = ptr::null_mut();
    publish(
        record,
        output,
        cache.text.as_mut_ptr().cast(),
        cache.text.len(),
        &mut result,
    )?;
    Ok(result)
}
fn pointer(result: Result<*mut Group, c_int>) -> *mut Group {
    match result {
        Ok(pointer) => pointer,
        Err(error) => {
            set_errno(error);
            ptr::null_mut()
        }
    }
}
#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub(super) unsafe extern "C" fn getgrgid(gid: groups::Gid) -> *mut Group {
    pointer(cached(Query::Gid(u32::from(gid))))
}
#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub(super) unsafe extern "C" fn getgrnam(name: *const c_char) -> *mut Group {
    pointer(named(name, cached, ptr::null_mut()))
}
#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub(super) unsafe extern "C" fn getgrgid_r(
    gid: groups::Gid,
    output: *mut Group,
    buffer: *mut c_char,
    length: usize,
    result: *mut *mut Group,
) -> c_int {
    (|| {
        if output.is_null() || result.is_null() {
            return Err(EFAULT);
        }
        user_copy::write(result.cast(), &0usize.to_ne_bytes())?;
        lookup(Query::Gid(u32::from(gid)), output, buffer, length, result)
    })()
    .err()
    .unwrap_or(0)
}
#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub(super) unsafe extern "C" fn getgrnam_r(
    name: *const c_char,
    output: *mut Group,
    buffer: *mut c_char,
    length: usize,
    result: *mut *mut Group,
) -> c_int {
    (|| {
        if output.is_null() || result.is_null() {
            return Err(EFAULT);
        }
        user_copy::write(result.cast(), &0usize.to_ne_bytes())?;
        named(
            name,
            |query| lookup(query, output, buffer, length, result),
            (),
        )
    })()
    .err()
    .unwrap_or(0)
}
