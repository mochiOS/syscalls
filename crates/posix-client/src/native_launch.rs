//! Common system-launch client. Sender-local Handle numbers never enter the
//! wire payload; native IPC attenuates explicitly attached references instead.
extern crate alloc;
use alloc::{string::String, vec::Vec};
use mochi_user_platform as p;
use p::capability::{application_launch as text, native_launch as wire};
use p::syscall::{EINVAL, EIO, SysError};

pub fn create_stopped(
    endpoint: u32,
    path: &str,
    label: &str,
    class: p::service::ExecutionClass,
    items: &[String],
) -> Result<u32, SysError> {
    let invalid = || SysError::from_raw(EINVAL as i64);
    let parsed = super::launch_arguments::collect_arguments(label, items).map_err(|_| invalid())?;
    let arguments: Vec<_> = parsed
        .arguments
        .iter()
        .map(|s| core::str::from_utf8(s))
        .collect::<Result<_, _>>()
        .map_err(|_| invalid())?;
    let environment: Vec<_> = parsed
        .environment
        .iter()
        .map(|s| core::str::from_utf8(s))
        .collect::<Result<_, _>>()
        .map_err(|_| invalid())?;
    let bindings: Vec<_> = parsed
        .handles
        .iter()
        .map(|h| wire::Binding {
            key: h.key,
            rights: h.rights,
        })
        .collect();
    let values: Vec<_> = parsed
        .values
        .iter()
        .map(|v| wire::Value {
            key: v.key,
            value: v.value,
        })
        .collect();
    let mut bytes = [0; wire::MAX_BYTES];
    let length = wire::encode(
        &wire::Request {
            class: class.as_raw(),
            text: text::Request {
                path,
                arguments: &arguments,
                environment: &environment,
                stdio_metadata: [0; 3],
            },
            bindings: &bindings,
            values: &values,
        },
        &mut bytes,
    )
    .map_err(|_| invalid())?;
    let mut handles = p::ipc::IpcObjectHandles::default();
    handles.count = parsed.handles.len() as u32;
    for (out, source) in handles.handles.iter_mut().zip(&parsed.handles) {
        *out = p::ipc::IpcObjectHandle {
            handle: source.source,
            reserved: 0,
            rights: source.rights | p::handle::HANDLE_RIGHT_TRANSFER,
        };
    }
    let borrowed = handles;
    let mut response = [0; 8];
    let message =
        p::ipc::call_object_handles(endpoint, &bytes[..length], &mut response, &mut handles)?;
    let rights = p::handle::HANDLE_RIGHT_WAIT
        | p::handle::HANDLE_RIGHT_SIGNAL
        | p::handle::HANDLE_RIGHT_DUPLICATE
        | p::handle::HANDLE_RIGHT_TRANSFER;
    if message as u32 as usize == response.len() && handles.is_user_delivery() {
        let status = u64::from_le_bytes(response);
        if status == 0
            && handles.count == 1
            && handles.handles[0].handle != 0
            && handles.handles[0].reserved == 0
            && handles.handles[0].rights == rights
        {
            return Ok(handles.handles[0].handle);
        }
        if status != 0 && handles.count == 0 {
            return Err(SysError::from_raw(status as i64));
        }
    }
    // A transport error above leaves source references borrowed. After a
    // successful IPC only delivered receiver references may be discarded.
    for h in handles.handles.iter().take(handles.count as usize) {
        if h.handle != 0
            && !borrowed
                .handles
                .iter()
                .take(borrowed.count as usize)
                .any(|b| b.handle == h.handle)
        {
            let _ = p::handle::close(h.handle);
        }
    }
    Err(SysError::from_raw(EIO as i64))
}
