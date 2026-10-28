//! Explicitly held DNS authority and positioned reads of immutable results.
//! No service discovery, FD namespace, ambient credential impersonation or
//! POSIX-service RPC is involved in operations on the returned job Handle.
use crate::{ClientError, ObjectHandleAttachment, ObjectHandles, ObjectTransport};
use mochios_net_device_protocol::resolver as wire;
pub use mochios_net_device_protocol::resolver::{
    A_SCOPE, AAAA_SCOPE, ALL_SCOPES, Kind, Limits, MAX_TIMEOUT, Name, Observation, PTR_SCOPE,
    ResultView,
};
pub const FACTORY_RIGHTS: u64 = mnu_abi::HANDLE_RIGHT_CONTROL
    | mnu_abi::HANDLE_RIGHT_DUPLICATE
    | mnu_abi::HANDLE_RIGHT_TRANSFER;
pub const JOB_RIGHTS: u64 =
    FACTORY_RIGHTS | mnu_abi::HANDLE_RIGHT_READ | mnu_abi::HANDLE_RIGHT_WAIT;

fn invoke<T: ObjectTransport>(
    transport: &T,
    op: u16,
    request: &[u8],
    source: Option<ObjectHandleAttachment<T::Handle>>,
    rights: Option<u64>,
) -> Result<Option<ObjectHandleAttachment<T::Handle>>, ClientError<T::Error>> {
    let mut handles = ObjectHandles::new();
    if let Some(source) = source {
        if source.handle == T::Handle::default()
            || source.rights & mnu_abi::HANDLE_RIGHT_CONTROL == 0
        {
            return Err(ClientError::Remote(-13));
        }
        handles
            .push(ObjectHandleAttachment {
                handle: source.handle,
                rights: mnu_abi::HANDLE_RIGHT_CONTROL,
            })
            .map_err(|_| ClientError::RequestTooLarge)?;
    }
    let borrowed = handles.clone();
    let mut response = [0; wire::REPLY_LEN];
    let outcome = transport
        .call_with_handles(request, &mut response, &mut handles)
        .map_err(ClientError::Transport);
    let checked = (|| {
        let n = outcome?;
        let bytes = response.get(..n).ok_or(ClientError::MismatchedResponse)?;
        let status = wire::reply_status(op, bytes).map_err(|_| ClientError::MismatchedResponse)?;
        if status != 0 {
            return Err(ClientError::Remote(status));
        }
        let Some(rights) = rights else {
            return if handles.is_empty() {
                Ok(None)
            } else {
                Err(ClientError::MismatchedResponse)
            };
        };
        if handles.len() != 1 {
            return Err(ClientError::MismatchedResponse);
        }
        let received = handles.get(0).unwrap();
        if received.handle == T::Handle::default()
            || source.is_some_and(|s| s.handle == received.handle)
            || received.rights != rights
        {
            return Err(ClientError::MismatchedResponse);
        }
        Ok(Some(received))
    })();
    if checked.is_err() {
        crate::drain_received_handles(&mut handles, &borrowed, |handle| {
            transport.close_received_handle(handle)
        });
    }
    checked
}
pub fn acquire<T: ObjectTransport>(
    transport: &T,
    limits: Limits,
) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
    let request = wire::scoped(wire::ACQUIRE, limits).map_err(|_| ClientError::Remote(-22))?;
    invoke(
        transport,
        wire::ACQUIRE,
        &request,
        None,
        Some(FACTORY_RIGHTS),
    )?
    .ok_or(ClientError::MismatchedResponse)
}
pub fn derive<T: ObjectTransport>(
    transport: &T,
    source: ObjectHandleAttachment<T::Handle>,
    limits: Limits,
) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
    let request = wire::scoped(wire::DERIVE, limits).map_err(|_| ClientError::Remote(-22))?;
    invoke(
        transport,
        wire::DERIVE,
        &request,
        Some(source),
        Some(FACTORY_RIGHTS),
    )?
    .ok_or(ClientError::MismatchedResponse)
}
pub fn validate<T: ObjectTransport>(
    transport: &T,
    source: ObjectHandleAttachment<T::Handle>,
) -> Result<(), ClientError<T::Error>> {
    invoke(
        transport,
        wire::VALIDATE,
        &wire::header(wire::VALIDATE),
        Some(source),
        None,
    )
    .map(|_| ())
}
pub fn start<T: ObjectTransport>(
    transport: &T,
    source: ObjectHandleAttachment<T::Handle>,
    kind: Kind,
    name: Name<'_>,
    timeout: u32,
) -> Result<ObjectHandleAttachment<T::Handle>, ClientError<T::Error>> {
    let mut bytes = [0; 24 + 255];
    let n = wire::Request {
        kind,
        name,
        timeout,
    }
    .encode(&mut bytes)
    .map_err(|_| ClientError::Remote(-22))?;
    invoke(
        transport,
        wire::OPEN,
        &bytes[..n],
        Some(source),
        Some(JOB_RIGHTS),
    )?
    .ok_or(ClientError::MismatchedResponse)
}

/// A borrowed native object, independent of the process's POSIX descriptor table.
pub trait Io<H: Copy> {
    type Error;
    fn query(&self, handle: H, tag: u64, out: &mut [u8]) -> Result<usize, Self::Error>;
    fn control(&self, handle: H, tag: u64, out: &mut [u8]) -> Result<usize, Self::Error>;
    fn read_at(&self, handle: H, offset: u64, out: &mut [u8]) -> Result<usize, Self::Error>;
}
pub fn limits<H: Copy, I: Io<H>>(io: &I, handle: H) -> Result<Limits, ClientError<I::Error>> {
    let mut data = [0; wire::LIMITS_LEN];
    let n = io
        .control(handle, wire::QUERY_LIMITS, &mut data)
        .map_err(ClientError::Transport)?;
    wire::Limits::decode(data.get(..n).ok_or(ClientError::MismatchedResponse)?)
        .map_err(|_| ClientError::MismatchedResponse)
}
pub fn observe<H: Copy, I: Io<H>>(io: &I, handle: H) -> Result<Observation, ClientError<I::Error>> {
    let mut data = [0; wire::OBSERVATION_LEN];
    let n = io
        .query(handle, wire::STATUS, &mut data)
        .map_err(ClientError::Transport)?;
    wire::Observation::decode(data.get(..n).ok_or(ClientError::MismatchedResponse)?)
        .map_err(|_| ClientError::MismatchedResponse)
}
pub fn cancel<H: Copy, I: Io<H>>(io: &I, handle: H) -> Result<bool, ClientError<I::Error>> {
    let mut data = [0; 4];
    let n = io
        .control(handle, wire::CANCEL, &mut data)
        .map_err(ClientError::Transport)?;
    if n != 4 {
        return Err(ClientError::MismatchedResponse);
    }
    match u32::from_le_bytes(data) {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ClientError::MismatchedResponse),
    }
}
/// Read a complete snapshot into caller-owned memory. A pending job returns
/// -11; the caller may wait on its native READABLE signal and retry. Result
/// status is DNS/service data, distinct from a failed native Handle operation.
pub fn snapshot<'a, H: Copy, I: Io<H>>(
    io: &I,
    handle: H,
    kind: Kind,
    question: Name<'_>,
    buffer: &'a mut [u8],
) -> Result<ResultView<'a>, ClientError<I::Error>> {
    let observation = observe(io, handle)?;
    if observation.kind != kind {
        return Err(ClientError::MismatchedResponse);
    }
    if !observation.ready {
        return Err(ClientError::Remote(-11));
    }
    let length = usize::try_from(observation.length).map_err(|_| ClientError::ResponseTooLarge)?;
    let out = buffer
        .get_mut(..length)
        .ok_or(ClientError::ResponseTooLarge)?;
    let mut offset = 0;
    while offset < length {
        let end = (offset + 4096).min(length);
        let n = io
            .read_at(handle, offset as u64, &mut out[offset..end])
            .map_err(ClientError::Transport)?;
        if n == 0 || n > end - offset {
            return Err(ClientError::MismatchedResponse);
        }
        offset += n;
    }
    let result = wire::decode_result(out).map_err(|_| ClientError::MismatchedResponse)?;
    if result.kind != kind
        || !result.question.matches(question)
        || result.status != observation.status
    {
        return Err(ClientError::MismatchedResponse);
    }
    Ok(result)
}

#[cfg(all(not(feature = "syscall-endpoint"), feature = "endpoint"))]
use mochi_user_platform::syscall as native;
#[cfg(feature = "syscall-endpoint")]
use mochi_user_syscall as native;
#[cfg(any(feature = "syscall-endpoint", feature = "endpoint"))]
#[derive(Clone, Copy, Default)]
pub struct NativeIo;
#[cfg(any(feature = "syscall-endpoint", feature = "endpoint"))]
impl NativeIo {
    fn bounded(count: u64, size: usize) -> Result<usize, native::SysError> {
        usize::try_from(count)
            .ok()
            .filter(|count| *count <= size)
            .ok_or_else(|| {
                native::SysError::from_raw(native::NativeError::BackingFailure.into_raw() as i64)
            })
    }
    fn metadata(
        &self,
        handle: u32,
        tag: u64,
        out: &mut [u8],
        op: native::SyscallNumber,
    ) -> Result<usize, native::SysError> {
        let n = native::call6(
            op,
            u64::from(handle),
            tag,
            0,
            0,
            out.as_mut_ptr() as u64,
            out.len() as u64,
        )?;
        Self::bounded(n, out.len())
    }
}
#[cfg(any(feature = "syscall-endpoint", feature = "endpoint"))]
impl Io<u32> for NativeIo {
    type Error = native::SysError;
    fn query(&self, handle: u32, tag: u64, out: &mut [u8]) -> Result<usize, Self::Error> {
        self.metadata(handle, tag, out, native::SyscallNumber::HandleQuery)
    }
    fn control(&self, handle: u32, tag: u64, out: &mut [u8]) -> Result<usize, Self::Error> {
        self.metadata(handle, tag, out, native::SyscallNumber::HandleControl)
    }
    fn read_at(&self, handle: u32, offset: u64, out: &mut [u8]) -> Result<usize, Self::Error> {
        let n = native::call4(
            native::SyscallNumber::HandleReadAt,
            u64::from(handle),
            out.as_mut_ptr() as u64,
            out.len() as u64,
            offset,
        )?;
        Self::bounded(n, out.len())
    }
}
