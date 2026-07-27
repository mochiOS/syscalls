use core::fmt;

use rustls::{CertificateError, Error, InvalidMessage};

use crate::verifier::{
    CERTIFICATE_SIZE_LIMIT_ERROR, CHAIN_BYTES_LIMIT_ERROR, CHAIN_DEPTH_LIMIT_ERROR,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsError {
    InvalidServerName,
    InvalidConfiguration,
    RandomUnavailable,
    TimeUnavailable,
    CertificateInvalid,
    HostnameMismatch,
    CertificateChainTooDeep,
    CertificateTooLarge,
    CertificateChainTooLarge,
    AuthenticationFailed,
    BufferLimit,
    Protocol,
    PeerAlert,
    InvalidState,
}

impl TlsError {
    pub(crate) fn from_rustls(error: &Error) -> Self {
        match error {
            Error::FailedToGetRandomBytes => Self::RandomUnavailable,
            Error::FailedToGetCurrentTime => Self::TimeUnavailable,
            Error::InvalidCertificate(CertificateError::NotValidForName)
            | Error::InvalidCertificate(CertificateError::NotValidForNameContext { .. }) => {
                Self::HostnameMismatch
            }
            Error::InvalidCertificate(_) | Error::NoCertificatesPresented => {
                Self::CertificateInvalid
            }
            Error::DecryptError => Self::AuthenticationFailed,
            Error::AlertReceived(_) => Self::PeerAlert,
            Error::General(message) if message == CHAIN_DEPTH_LIMIT_ERROR => {
                Self::CertificateChainTooDeep
            }
            Error::General(message) if message == CERTIFICATE_SIZE_LIMIT_ERROR => {
                Self::CertificateTooLarge
            }
            Error::General(message) if message == CHAIN_BYTES_LIMIT_ERROR => {
                Self::CertificateChainTooLarge
            }
            Error::InvalidMessage(
                InvalidMessage::CertificatePayloadTooLarge
                | InvalidMessage::HandshakePayloadTooLarge
                | InvalidMessage::MessageTooLarge,
            ) => Self::BufferLimit,
            _ => Self::Protocol,
        }
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidServerName => "invalid TLS server name",
            Self::InvalidConfiguration => "invalid TLS configuration",
            Self::RandomUnavailable => "cryptographic random source unavailable",
            Self::TimeUnavailable => "UTC wall clock unavailable",
            Self::CertificateInvalid => "server certificate validation failed",
            Self::HostnameMismatch => "server certificate hostname mismatch",
            Self::CertificateChainTooDeep => "server certificate chain is too deep",
            Self::CertificateTooLarge => "server certificate is too large",
            Self::CertificateChainTooLarge => "server certificate chain is too large",
            Self::AuthenticationFailed => "TLS record authentication failed",
            Self::BufferLimit => "TLS buffer limit exceeded",
            Self::Protocol => "TLS protocol error",
            Self::PeerAlert => "TLS peer sent a fatal alert",
            Self::InvalidState => "invalid TLS connection state",
        })
    }
}
