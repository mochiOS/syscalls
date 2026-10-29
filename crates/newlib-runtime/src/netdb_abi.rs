//! C resolver transactions with explicit backend ownership. Callers supply
//! a concrete Backend; tests use these same transactions with fixture
//! data. No backend or C result is borrowed across an abandoned callback frame.
use super::netdb_memory::{AddrInfo, Inputs, List, NameOutputs, sockaddr};
use super::*;
use core::cell::Cell;
use mochios_posix_client::netdb::{self as policy, Backend, Error};

fn remember(error: &Cell<Option<Error>>, value: Error) -> c_int {
    error.set(Some(value));
    EINVAL
}
fn finish(result: Result<c_int, c_int>, error: Option<Error>) -> c_int {
    match result {
        Ok(value) => value,
        Err(errno) => {
            let error = error.unwrap_or_else(|| {
                Error::System(mochios_posix_client::newlib_errno::to_status(errno))
            });
            if let Error::System(status) = error {
                set_errno(mochios_posix_client::newlib_errno::from_status(i64::from(
                    status,
                )));
            }
            error.code()
        }
    }
}

/// The backend is moved into the registered resource owner before lookup.
/// On success only the C result list escapes; on every failure its prefix and
/// all backend resources are reclaimed before the final errno is published.
pub(super) fn getaddrinfo<B: Backend>(
    backend: B,
    node: *const c_char,
    service: *const c_char,
    hints: *const AddrInfo,
    result: *mut *mut AddrInfo,
) -> c_int {
    let error = Cell::new(None);
    let operation = io_resources::with_initialized(
        || Ok((Inputs::new(), List::new(), backend)),
        |(inputs, _, _)| {
            inputs
                .capture(node, service, hints, result)
                .map_err(|e| remember(&error, e))
        },
        |(inputs, list, backend)| {
            policy::getaddrinfo(
                backend,
                inputs.node(),
                inputs.service(),
                inputs.hints,
                &mut |entry| list.append(entry),
            )
            .map_err(|e| remember(&error, e))?;
            list.publish(result).map_err(|e| remember(&error, e))?;
            Ok(0)
        },
    );
    finish(operation, error.get())
}

pub(super) fn getnameinfo<B: Backend>(
    backend: B,
    address: *const c_void,
    address_length: u32,
    host: *mut c_char,
    host_length: u32,
    service: *mut c_char,
    service_length: u32,
    flags: c_int,
) -> c_int {
    let error = Cell::new(None);
    let operation = io_resources::with_initialized(
        || {
            let outputs = NameOutputs::new(host, host_length, service, service_length)
                .map_err(|e| remember(&error, e))?;
            Ok((
                outputs,
                None,
                [0; policy::NI_MAXHOST],
                [0; policy::NI_MAXSERV],
                backend,
            ))
        },
        |(_, captured, _, _, _)| {
            *captured = Some(sockaddr(address, address_length).map_err(|e| remember(&error, e))?);
            Ok(())
        },
        |(outputs, captured, host, service, backend)| {
            let (address, port) = captured.ok_or_else(|| remember(&error, Error::Fail))?;
            policy::getnameinfo(
                backend,
                address,
                port,
                flags,
                outputs.wants_host().then_some(host.as_mut_slice()),
                outputs.wants_service().then_some(service.as_mut_slice()),
            )
            .map_err(|e| remember(&error, e))?;
            let host_length = if outputs.wants_host() {
                host.iter()
                    .position(|b| *b == 0)
                    .ok_or_else(|| remember(&error, Error::Fail))?
                    + 1
            } else {
                0
            };
            let service_length = if outputs.wants_service() {
                service
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or_else(|| remember(&error, Error::Fail))?
                    + 1
            } else {
                0
            };
            outputs
                .publish(&host[..host_length], &service[..service_length])
                .map_err(|e| remember(&error, e))?;
            Ok(0)
        },
    );
    finish(operation, error.get())
}
