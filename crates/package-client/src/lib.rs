//! Shared GUI/CLI package transaction client. Password entry and administrator
//! policy belong to the common broker, not to individual applications.
use mochi_user_platform as p;
use mochios_package_protocol::{self as protocol, Request, transaction as wire};
use std::{
    io,
    sync::atomic::{AtomicU64, Ordering},
};

pub struct Expected<'a> {
    pub package_id: &'a str,
    pub version: &'a str,
    pub source_digest: [u8; 32],
}
struct Reference(u32);
impl Drop for Reference {
    fn drop(&mut self) {
        let _ = p::handle::close(self.0);
    }
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "package authorization was rejected",
    )
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid package transaction response",
    )
}
fn native(error: p::syscall::SysError) -> io::Error {
    io::Error::from_raw_os_error(error.errno().unwrap_or(libc::EIO as u64) as i32)
}
fn id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}
struct Received {
    objects: p::ipc::IpcObjectHandles,
    borrowed: Vec<u32>,
    length: usize,
}
impl Drop for Received {
    fn drop(&mut self) {
        let objects =
            &self.objects.handles[..(self.objects.count as usize).min(self.objects.handles.len())];
        for (i, object) in objects.iter().enumerate() {
            if object.handle != 0
                && !self.borrowed.contains(&object.handle)
                && !objects[..i].iter().any(|old| old.handle == object.handle)
            {
                let _ = p::handle::close(object.handle);
            }
        }
    }
}
fn call(
    endpoint: u32,
    canonical: u64,
    request: &[u8],
    attached: &[p::ipc::IpcObjectHandle],
    output: &mut [u8],
) -> io::Result<Received> {
    let mut reply = Received {
        objects: p::ipc::IpcObjectHandles::default(),
        borrowed: attached.iter().map(|o| o.handle).collect(),
        length: 0,
    };
    if attached.len() > reply.objects.handles.len() {
        return Err(invalid());
    }
    reply.objects.count = attached.len() as u32;
    reply.objects.handles[..attached.len()].copy_from_slice(attached);
    let message = p::ipc::call_object_handles(endpoint, request, output, &mut reply.objects)
        .map_err(native)?;
    reply.length = message as u32 as usize;
    if message >> 32 != canonical
        || reply.length > output.len()
        || reply.objects.delivery_flags != 0
        || reply.objects.count as usize > reply.objects.handles.len()
    {
        return Err(invalid());
    }
    Ok(reply)
}
fn status(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() != 8 {
        return Err(invalid());
    }
    match u64::from_le_bytes(bytes.try_into().unwrap()) {
        0 => Ok(()),
        n @ 1..=4095 => Err(native(p::syscall::SysError::from_raw(-(n as i64)))),
        _ => Err(invalid()),
    }
}
fn broker(endpoint: u32) -> io::Result<()> {
    if p::capability::check_thread(u64::from(endpoint), "capabilities.manage") == Ok(1) {
        Ok(())
    } else {
        Err(denied())
    }
}
fn package_endpoint(broker_endpoint: u32) -> io::Result<(Reference, u64)> {
    broker(broker_endpoint)?;
    let mut bytes = [0; 16];
    let mut response = call(
        broker_endpoint,
        u64::from(broker_endpoint),
        &p::capability::administrator::PACKAGE_CONNECT_OPCODE.to_le_bytes(),
        &[],
        &mut bytes,
    )?;
    broker(broker_endpoint)?;
    if response.length == 8 {
        status(&bytes[..8])?;
        return Err(invalid());
    }
    if response.length != 16 {
        return Err(invalid());
    }
    status(&bytes[..8])?;
    let canonical = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    if canonical == 0
        || response.objects.count != 1
        || response.objects.handles[0].reserved != 0
        || response.objects.handles[0].handle == 0
        || response.objects.handles[0].rights
            != p::handle::HANDLE_RIGHT_SEND | p::handle::HANDLE_RIGHT_TRANSFER
    {
        return Err(invalid());
    }
    let handle = Reference(response.objects.handles[0].handle);
    response.objects.handles[0].handle = 0;
    Ok((handle, canonical))
}
#[cfg(target_os = "mochios")]
fn open_package(path: &str) -> io::Result<Reference> {
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > wire::MAX_PACKAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a regular package file within the size limit",
        ));
    }
    unsafe extern "C" {
        fn mochi_fd_export(
            fd: i32,
            rights: u64,
            output: *mut mochios_posix_protocol::ExportedFdHandle,
        ) -> i32;
    }
    let mut exported = mochios_posix_protocol::ExportedFdHandle::default();
    let rights = p::handle::HANDLE_RIGHT_READ | p::handle::HANDLE_RIGHT_TRANSFER;
    // Only this process's pinned descriptor is exported; no foreign FD lookup.
    if unsafe { mochi_fd_export(file.as_raw_fd(), rights, &mut exported) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let object = Reference(exported.handle);
    if exported.reserved != 0 || exported.handle == 0 || exported.rights != rights {
        return Err(invalid());
    }
    Ok(object)
}
#[cfg(not(target_os = "mochios"))]
fn open_package(_: &str) -> io::Result<Reference> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "package transactions require mochiOS",
    ))
}

/// Capture, authenticate and commit exactly one operation. A failed or expired
/// transaction is never silently retried with a different package/version.
pub fn mutate(request: Request<'_>, expected: Option<Expected<'_>>) -> io::Result<()> {
    let (mutation, subject, path) = match request {
        Request::Install(path) => (wire::Mutation::Install, "", Some(path)),
        Request::Update(path) => (wire::Mutation::Update, "", Some(path)),
        Request::Remove(id) => (wire::Mutation::Remove, id, None),
        Request::List => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected a package change",
            ));
        }
    };
    let broker_endpoint =
        u32::try_from(p::process::find_by_name("capability.service").map_err(native)?)
            .map_err(|_| invalid())?;
    let (package, canonical) = package_endpoint(broker_endpoint)?;
    let input = path.map(open_package).transpose()?;
    let attached = input.as_ref().map(|file| p::ipc::IpcObjectHandle {
        handle: file.0,
        reserved: 0,
        rights: p::handle::HANDLE_RIGHT_READ | p::handle::HANDLE_RIGHT_TRANSFER,
    });
    let mut request = [0; protocol::HEADER_LEN + protocol::MAX_PACKAGE_ID_LEN];
    let request_id = id();
    let length =
        wire::encode_prepare(request_id, mutation, subject, &mut request).map_err(|_| invalid())?;
    let mut response = [0; wire::MAX_PLAN_BYTES];
    let mut prepared = call(
        package.0,
        canonical,
        &request[..length],
        attached.as_slice(),
        &mut response,
    )?;
    let bytes = &response[..prepared.length];
    if let Ok(status) = protocol::decode_status(bytes, request_id) {
        return Err(if status < 0 {
            native(p::syscall::SysError::from_raw(i64::from(status)))
        } else {
            invalid()
        });
    }
    let info = wire::decode_plan(bytes, request_id).map_err(|_| invalid())?;
    if info.mutation != mutation
        || (mutation == wire::Mutation::Remove && info.package_id != subject)
    {
        return Err(invalid());
    }
    if let Some(expected) = expected {
        if info.package_id != expected.package_id
            || info.version != expected.version
            || info.source_digest != expected.source_digest
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the prepared package differs from the selected release",
            ));
        }
    }
    if prepared.objects.count != 1
        || prepared.objects.handles[0].reserved != 0
        || prepared.objects.handles[0].handle == 0
        || prepared.objects.handles[0].rights != wire::PLAN_RIGHTS
    {
        return Err(invalid());
    }
    let plan = Reference(prepared.objects.handles[0].handle);
    prepared.objects.handles[0].handle = 0;
    let object = p::ipc::IpcObjectHandle {
        handle: plan.0,
        reserved: 0,
        rights: p::handle::HANDLE_RIGHT_TRANSFER,
    };
    broker(broker_endpoint)?;
    let mut result = [0; 8];
    let receipt = call(
        broker_endpoint,
        u64::from(broker_endpoint),
        &p::capability::administrator::PACKAGE_OPCODE.to_le_bytes(),
        &[object],
        &mut result,
    )?;
    broker(broker_endpoint)?;
    if receipt.objects.count != 0 {
        return Err(invalid());
    }
    status(&result[..receipt.length])?;
    let request_id = id();
    let length = wire::encode_command(request_id, true, &mut request).map_err(|_| invalid())?;
    let mut result = [0; protocol::HEADER_LEN];
    let response = call(
        package.0,
        canonical,
        &request[..length],
        &[object],
        &mut result,
    )?;
    if response.objects.count != 0 {
        return Err(invalid());
    }
    match protocol::decode_status(&result[..response.length], request_id).map_err(|_| invalid())? {
        0 => Ok(()),
        status if status < 0 => Err(native(p::syscall::SysError::from_raw(i64::from(status)))),
        _ => Err(invalid()),
    }
}

pub struct InstalledPackage {
    pub package_id: String,
    pub name: String,
    pub version: String,
    pub kind: String,
    pub flags: u32,
}
/// Read-only enumeration uses the same authenticated endpoint discovery.
pub fn installed() -> io::Result<Vec<InstalledPackage>> {
    let broker = u32::try_from(p::process::find_by_name("capability.service").map_err(native)?)
        .map_err(|_| invalid())?;
    let (package, canonical) = package_endpoint(broker)?;
    let mut request = [0; protocol::HEADER_LEN];
    let id = id();
    let length =
        protocol::encode_request(id, Request::List, &mut request).map_err(|_| invalid())?;
    let mut bytes = vec![0; protocol::MAX_MESSAGE_LEN];
    let result = call(package.0, canonical, &request[..length], &[], &mut bytes)?;
    if result.objects.count != 0 {
        return Err(invalid());
    }
    let bytes = &bytes[..result.length];
    if let Ok(status) = protocol::decode_status(bytes, id) {
        return Err(if status < 0 {
            native(p::syscall::SysError::from_raw(i64::from(status)))
        } else {
            invalid()
        });
    }
    protocol::decode_list(bytes, id)
        .map_err(|_| invalid())?
        .map(|record| {
            let record = record.map_err(|_| invalid())?;
            Ok(InstalledPackage {
                package_id: record.package_id.into(),
                name: record.name.into(),
                version: record.version.into(),
                kind: record.kind.into(),
                flags: record.flags,
            })
        })
        .collect()
}
