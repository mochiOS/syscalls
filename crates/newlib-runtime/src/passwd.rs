//! Reentrant public-account lookup. Caller storage is accessed through MemoryCopy.
use super::*;
use posix_protocol::account::{self as wire, Query, Record};

#[repr(C)]
pub(super) struct Passwd {
    name: *mut c_char,
    password: *mut c_char,
    uid: u32,
    gid: u32,
    comment: *mut c_char,
    gecos: *mut c_char,
    home: *mut c_char,
    shell: *mut c_char,
}
const _: () = {
    assert!(core::mem::size_of::<Passwd>() == 56);
    assert!(core::mem::offset_of!(Passwd, uid) == 16);
    assert!(core::mem::offset_of!(Passwd, home) == 40);
};

fn publish(
    record: Record<'_>,
    output: *mut Passwd,
    buffer: *mut c_char,
    length: usize,
    result: *mut *mut Passwd,
) -> Result<(), c_int> {
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
    bytes[16..20].copy_from_slice(&record.uid.to_ne_bytes());
    bytes[20..24].copy_from_slice(&record.gid.to_ne_bytes());
    user_copy::write(buffer.cast(), &text[..required])?;
    user_copy::write(output.cast(), &bytes)?;
    user_copy::write(result.cast(), &(output as usize).to_ne_bytes())
}

fn lookup(
    query: Query<'_>,
    output: *mut Passwd,
    buffer: *mut c_char,
    length: usize,
    result: *mut *mut Passwd,
) -> Result<(), c_int> {
    let client = posix_client().map_err(map_posix_client_error)?;
    let mut response = [0; wire::MAX_RECORD];
    let n = match client
        .lookup_account(query, &mut response)
        .map_err(map_posix_client_error)
    {
        Ok(n) => n,
        Err(ENOENT) => return Ok(()),
        Err(error) => return Err(error),
    };
    let record = wire::decode_record(&response[..n]).map_err(|_| EIO)?;
    publish(record, output, buffer, length, result)
}

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn getpwuid_r(
    uid: u32,
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
        lookup(Query::Uid(uid), output, buffer, length, result)
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
        let n = match user_copy::capture_text(name, &mut bytes, ENOENT) {
            Ok(n) => n,
            Err(ENOENT) => return Ok(()),
            Err(error) => return Err(error),
        };
        let name = match core::str::from_utf8(&bytes[..n]) {
            Ok(name)
                if !name.is_empty()
                    && name
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-')) =>
            {
                name
            }
            _ => return Ok(()),
        };
        lookup(Query::Name(name), output, buffer, length, result)
    })();
    operation.err().unwrap_or(0)
}
