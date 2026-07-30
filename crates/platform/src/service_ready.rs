use core::sync::atomic::{AtomicU64, Ordering};

pub const MESSAGE_LEN: usize = 20;

const MAGIC: u32 = 0x5952_4453;
const VERSION: u16 = 1;
const KIND_NOTIFICATION: u16 = 1;
const BOOTSTRAP_ARG_PREFIX: &[u8] = b"--service-ready=";

static BOOTSTRAP_ENDPOINT: AtomicU64 = AtomicU64::new(0);
static BOOTSTRAP_TOKEN: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub endpoint: u64,
    pub token: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OneShotStatus(Option<i32>);

impl OneShotStatus {
    pub const fn new() -> Self {
        Self(None)
    }

    pub const fn get(self) -> Option<i32> {
        self.0
    }

    pub fn record(&mut self, status: i32) -> bool {
        if self.0.is_some() {
            return false;
        }
        self.0 = Some(status);
        true
    }
}

impl Default for OneShotStatus {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    InvalidKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultError {
    InvalidMessage(DecodeError),
    TokenMismatch,
    Failed(i32),
}

fn parse_decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0u64;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?;
        value = value.checked_add(u64::from(byte - b'0'))?;
    }
    Some(value)
}

pub fn capture_bootstrap_arg(arg: &[u8]) {
    let Some(value) = arg.strip_prefix(BOOTSTRAP_ARG_PREFIX) else {
        return;
    };
    let Some(separator) = value.iter().position(|byte| *byte == b':') else {
        return;
    };
    let Some(endpoint) = parse_decimal(&value[..separator]) else {
        return;
    };
    let Some(token) = parse_decimal(&value[separator + 1..]) else {
        return;
    };
    if endpoint == 0 || token == 0 {
        return;
    }
    BOOTSTRAP_ENDPOINT.store(endpoint, Ordering::Relaxed);
    BOOTSTRAP_TOKEN.store(token, Ordering::Relaxed);
}

pub fn take_bootstrap_target() -> Option<Target> {
    let endpoint = BOOTSTRAP_ENDPOINT.swap(0, Ordering::Relaxed);
    let token = BOOTSTRAP_TOKEN.swap(0, Ordering::Relaxed);
    if endpoint == 0 || token == 0 {
        None
    } else {
        Some(Target { endpoint, token })
    }
}

pub fn notification(token: u64, status: i32) -> [u8; MESSAGE_LEN] {
    let mut message = [0u8; MESSAGE_LEN];
    message[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    message[4..6].copy_from_slice(&VERSION.to_le_bytes());
    message[6..8].copy_from_slice(&KIND_NOTIFICATION.to_le_bytes());
    message[8..16].copy_from_slice(&token.to_le_bytes());
    message[16..20].copy_from_slice(&status.to_le_bytes());
    message
}

pub fn decode_notification(message: &[u8]) -> Result<(u64, i32), DecodeError> {
    if message.len() != MESSAGE_LEN {
        return Err(DecodeError::InvalidLength);
    }
    let magic = u32::from_le_bytes([message[0], message[1], message[2], message[3]]);
    if magic != MAGIC {
        return Err(DecodeError::InvalidMagic);
    }
    let version = u16::from_le_bytes([message[4], message[5]]);
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion);
    }
    let kind = u16::from_le_bytes([message[6], message[7]]);
    if kind != KIND_NOTIFICATION {
        return Err(DecodeError::InvalidKind);
    }
    let token = u64::from_le_bytes([
        message[8],
        message[9],
        message[10],
        message[11],
        message[12],
        message[13],
        message[14],
        message[15],
    ]);
    let status = i32::from_le_bytes([message[16], message[17], message[18], message[19]]);
    Ok((token, status))
}

pub fn validate_notification(message: &[u8], expected_token: u64) -> Result<(), ResultError> {
    let (token, status) = decode_notification(message).map_err(ResultError::InvalidMessage)?;
    if token != expected_token {
        return Err(ResultError::TokenMismatch);
    }
    if status != 0 {
        return Err(ResultError::Failed(status));
    }
    Ok(())
}

#[cfg(not(test))]
pub fn generate_token() -> super::syscall::SysResult<u64> {
    let mut token = 0u64;
    let written = super::syscall::call3(
        super::syscall::SyscallNumber::Getrandom,
        core::ptr::addr_of_mut!(token) as u64,
        core::mem::size_of::<u64>() as u64,
        0,
    )?;
    if written != core::mem::size_of::<u64>() as u64 || token == 0 {
        return Err(super::syscall::SysError::from_raw(
            super::syscall::EIO as i64,
        ));
    }
    Ok(token)
}

#[cfg(not(test))]
pub fn notify(target: Target, status: i32) -> super::syscall::SysResult<u64> {
    super::ipc::send(target.endpoint, &notification(target.token, status))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_has_stable_encoding() {
        assert_eq!(
            notification(0x0807_0605_0403_0201, -5),
            [
                0x53, 0x44, 0x52, 0x59, 1, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0xfb, 0xff, 0xff, 0xff,
            ]
        );
    }

    #[test]
    fn validates_token_and_status() {
        assert_eq!(validate_notification(&notification(7, 0), 7), Ok(()));
        assert_eq!(
            validate_notification(&notification(8, 0), 7),
            Err(ResultError::TokenMismatch)
        );
        assert_eq!(
            validate_notification(&notification(7, -5), 7),
            Err(ResultError::Failed(-5))
        );
    }

    #[test]
    fn rejects_short_and_unaligned_messages() {
        assert_eq!(
            decode_notification(&notification(7, 0)[..MESSAGE_LEN - 1]),
            Err(DecodeError::InvalidLength)
        );

        let mut storage = [0u8; MESSAGE_LEN + 1];
        storage[1..].copy_from_slice(&notification(7, 0));
        assert_eq!(decode_notification(&storage[1..]), Ok((7, 0)));
    }

    #[test]
    fn rejects_invalid_header_and_kind() {
        let mut invalid_magic = notification(7, 0);
        invalid_magic[0] ^= 0xff;
        assert_eq!(
            decode_notification(&invalid_magic),
            Err(DecodeError::InvalidMagic)
        );

        let mut invalid_version = notification(7, 0);
        invalid_version[4] = 2;
        assert_eq!(
            decode_notification(&invalid_version),
            Err(DecodeError::UnsupportedVersion)
        );

        let mut invalid_kind = notification(7, 0);
        invalid_kind[6] = 2;
        assert_eq!(
            decode_notification(&invalid_kind),
            Err(DecodeError::InvalidKind)
        );
    }

    #[test]
    fn captures_bootstrap_target_once() {
        capture_bootstrap_arg(b"--service-ready=42:99");
        assert_eq!(
            take_bootstrap_target(),
            Some(Target {
                endpoint: 42,
                token: 99,
            })
        );
        assert_eq!(take_bootstrap_target(), None);
    }

    #[test]
    fn rejects_malformed_bootstrap_target() {
        capture_bootstrap_arg(b"--service-ready=0:99");
        assert_eq!(take_bootstrap_target(), None);
        capture_bootstrap_arg(b"--service-ready=42:not-a-token");
        assert_eq!(take_bootstrap_target(), None);
    }

    #[test]
    fn duplicate_notification_keeps_first_status() {
        let mut status = OneShotStatus::new();
        assert!(status.record(0));
        assert!(!status.record(-5));
        assert_eq!(status.get(), Some(0));
    }
}
