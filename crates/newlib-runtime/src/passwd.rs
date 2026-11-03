//! Public-account lookup. Caller storage is accessed through MemoryCopy.
use super::*;
use posix_protocol::account::{self as wire, Query, Record};

#[repr(C)]
pub(super) struct Passwd {
    name: *mut c_char,
    password: *mut c_char,
    uid: u16,
    gid: u16,
    comment: *mut c_char,
    gecos: *mut c_char,
    home: *mut c_char,
    shell: *mut c_char,
}
const _: () = {
    assert!(core::mem::size_of::<Passwd>() == 56);
    assert!(core::mem::offset_of!(Passwd, uid) == 16);
    assert!(core::mem::offset_of!(Passwd, gid) == 18);
    assert!(core::mem::offset_of!(Passwd, home) == 40);
};

// newlib's generic x86_64-elf uid_t/gid_t are unsigned short. The wire uses
// u32; do not truncate an account that the public C layout cannot represent.
#[repr(align(8))]
pub(super) struct Cache {
    record: [u8; 56],
    text: [u8; wire::MAX_RECORD + 8],
}
impl Cache {
    pub const fn new() -> Self {
        Self {
            record: [0; 56],
            text: [0; wire::MAX_RECORD + 8],
        }
    }
}

fn publish(
    record: Record<'_>,
    output: *mut Passwd,
    buffer: *mut c_char,
    length: usize,
    result: *mut *mut Passwd,
) -> Result<(), c_int> {
    let uid = u16::try_from(record.uid).map_err(|_| EOVERFLOW)?;
    let gid = u16::try_from(record.gid).map_err(|_| EOVERFLOW)?;
    let strings = [
        record.name,
        "x",
        record.display_name,
        record.home,
        record.shell,
    ];
    let required = strings.iter().try_fold(0usize, |n, value| {
        n.checked_add(value.len() + 1).ok_or(EOVERFLOW)
    })?;
    if required > length {
        return Err(ERANGE);
    }
    if output.is_null() || buffer.is_null() {
        return Err(EFAULT);
    }
    let base = buffer as usize;
    base.checked_add(required).ok_or(EFAULT)?;
    let mut text = [0u8; wire::MAX_RECORD + 8];
    let mut pointers = [0usize; 5];
    let mut offset = 0;
    for (index, value) in strings.iter().enumerate() {
        pointers[index] = base + offset;
        text[offset..offset + value.len()].copy_from_slice(value.as_bytes());
        offset += value.len() + 1;
    }
    let mut bytes = [0u8; 56];
    for (offset, pointer) in [
        (0, pointers[0]),
        (8, pointers[1]),
        (24, pointers[2]),
        (32, pointers[2]),
        (40, pointers[3]),
        (48, pointers[4]),
    ] {
        bytes[offset..offset + 8].copy_from_slice(&pointer.to_ne_bytes());
    }
    bytes[16..18].copy_from_slice(&uid.to_ne_bytes());
    bytes[18..20].copy_from_slice(&gid.to_ne_bytes());
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
        .lookup_account(query, response)
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
    output: *mut Passwd,
    buffer: *mut c_char,
    length: usize,
    result: *mut *mut Passwd,
) -> Result<(), c_int> {
    if let Some(record) = fetch(query, &mut [0; wire::MAX_RECORD])? {
        publish(record, output, buffer, length, result)?;
    }
    Ok(())
}

fn capture_name<'a>(
    name: *const c_char,
    bytes: &'a mut [u8; wire::MAX_NAME],
) -> Result<Option<&'a str>, c_int> {
    let n = match user_copy::capture_text(name, bytes, ENOENT) {
        Ok(n) => n,
        Err(ENOENT) => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(core::str::from_utf8(&bytes[..n]).ok().filter(|name| {
        !name.is_empty()
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-'))
    }))
}

fn cached(query: Query<'_>) -> Result<*mut Passwd, c_int> {
    // Complete RPC before locking the process-local result. Transport and
    // error reporting may themselves need STATE. Its existing fork protocol
    // also protects this cache; do not add a separate inherited mutex.
    let mut response = [0; wire::MAX_RECORD];
    let Some(record) = fetch(query, &mut response)? else {
        return Ok(ptr::null_mut());
    };
    let mut state = STATE.lock();
    let cache = &mut state.passwd;
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

fn pointer_result(result: Result<*mut Passwd, c_int>) -> *mut Passwd {
    match result {
        Ok(pointer) => pointer,
        Err(error) => {
            set_errno(error);
            ptr::null_mut()
        }
    }
}

#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub(super) unsafe extern "C" fn getpwuid(uid: u16) -> *mut Passwd {
    pointer_result(cached(Query::Uid(u32::from(uid))))
}

#[cfg_attr(target_os = "mochios", unsafe(no_mangle))]
pub(super) unsafe extern "C" fn getpwnam(name: *const c_char) -> *mut Passwd {
    let result = (|| {
        let mut bytes = [0; wire::MAX_NAME];
        match capture_name(name, &mut bytes)? {
            Some(name) => cached(Query::Name(name)),
            None => Ok(ptr::null_mut()),
        }
    })();
    pointer_result(result)
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn getpwuid_r(
    uid: u16,
    output: *mut Passwd,
    buffer: *mut c_char,
    length: usize,
    result: *mut *mut Passwd,
) -> c_int {
    let operation = (|| {
        if result.is_null() || output.is_null() {
            return Err(EFAULT);
        }
        user_copy::write(result.cast(), &0usize.to_ne_bytes())?;
        lookup(Query::Uid(u32::from(uid)), output, buffer, length, result)
    })();
    operation.err().unwrap_or(0)
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn getpwnam_r(
    name: *const c_char,
    output: *mut Passwd,
    buffer: *mut c_char,
    length: usize,
    result: *mut *mut Passwd,
) -> c_int {
    let operation = (|| {
        if result.is_null() || output.is_null() {
            return Err(EFAULT);
        }
        user_copy::write(result.cast(), &0usize.to_ne_bytes())?;
        let mut bytes = [0; wire::MAX_NAME];
        let Some(name) = capture_name(name, &mut bytes)? else {
            return Ok(());
        };
        lookup(Query::Name(name), output, buffer, length, result)
    })();
    operation.err().unwrap_or(0)
}
