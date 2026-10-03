#![no_std]

extern crate alloc;

use core::sync::atomic::{AtomicU64, Ordering};

use mochios_posix_protocol as protocol;

pub mod fd;

const CONTROL_MESSAGE_LEN: usize = 4096;

pub trait Transport {
    type Error;

    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientError<E> {
    Transport(E),
    Protocol(protocol::ProtocolError),
    RequestTooLarge,
    ResponseTooLarge,
    MismatchedResponse,
    Remote(i32),
}

pub struct Client<T> {
    transport: T,
    next_request_id: AtomicU64,
}

impl<T: Transport> Client<T> {
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            next_request_id: AtomicU64::new(1),
        }
    }

    pub fn ping(&self) -> Result<(), ClientError<T::Error>> {
        let mut response = [];
        self.request(protocol::OP_PING, 0, &[], &mut response)
            .map(|_| ())
    }

    pub fn request(
        &self,
        opcode: u16,
        flags: u32,
        payload: &[u8],
        response_payload: &mut [u8],
    ) -> Result<usize, ClientError<T::Error>> {
        if payload.len() > CONTROL_MESSAGE_LEN - protocol::HEADER_LEN {
            return Err(ClientError::RequestTooLarge);
        }
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let mut request_bytes = [0u8; CONTROL_MESSAGE_LEN];
        let request_len = protocol::encode(
            protocol::Header {
                opcode,
                request_id,
                flags,
                payload_len: payload.len() as u32,
                status: protocol::STATUS_OK,
            },
            payload,
            &mut request_bytes,
        )
        .map_err(ClientError::Protocol)?;

        let mut response_bytes = [0u8; CONTROL_MESSAGE_LEN];
        let response_len = self
            .transport
            .call(&request_bytes[..request_len], &mut response_bytes)
            .map_err(ClientError::Transport)?;
        let response_bytes = response_bytes
            .get(..response_len)
            .ok_or(ClientError::ResponseTooLarge)?;
        let (header, payload) = protocol::decode(response_bytes).map_err(ClientError::Protocol)?;
        if header.opcode != protocol::OP_STATUS || header.request_id != request_id {
            return Err(ClientError::MismatchedResponse);
        }
        if header.status != protocol::STATUS_OK {
            return Err(ClientError::Remote(header.status));
        }
        if payload.len() > response_payload.len() {
            return Err(ClientError::ResponseTooLarge);
        }
        response_payload[..payload.len()].copy_from_slice(payload);
        Ok(payload.len())
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointTransport {
    endpoint: u64,
}

impl EndpointTransport {
    pub const fn new(endpoint: u64) -> Self {
        Self { endpoint }
    }

    pub const fn endpoint(self) -> u64 {
        self.endpoint
    }
}

impl Transport for EndpointTransport {
    type Error = mochi_user_platform::syscall::SysError;

    fn call(&self, request: &[u8], response: &mut [u8]) -> Result<usize, Self::Error> {
        let received = mochi_user_platform::ipc::call(self.endpoint, request, response)?;
        let length = (received & 0xffff_ffff) as usize;
        if length > response.len() {
            return Err(mochi_user_platform::syscall::SysError::from_raw(
                mochi_user_platform::syscall::EOVERFLOW as i64,
            ));
        }
        Ok(length)
    }
}
