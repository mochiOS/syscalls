use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use rustls::client::{ClientConfig, UnbufferedClientConnection};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::unbuffered::{ConnectionState, EncodeError, EncryptError};
use rustls::{CipherSuite, ProtocolVersion};
use x509_cert::Certificate;
use x509_cert::der::Decode;

use crate::{
    MAX_PEER_CERTIFICATE_NAME_LEN, MAX_TLS_HANDSHAKE_BUFFER, MAX_TLS_HOSTNAME_LEN,
    MAX_TLS_PLAINTEXT, MAX_TLS_RECORD, TlsError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsState {
    Handshaking,
    Established,
    Closing,
    PeerClosed,
    Closed,
    Failed,
}

#[derive(Debug, Eq, PartialEq)]
pub enum TlsEvent {
    Transmit(Vec<u8>),
    NeedReceive,
    Established,
    Plaintext(Vec<u8>),
    PeerClosed,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerCertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub not_before: u64,
    pub not_after: u64,
}

enum Step {
    Continue,
    Event(TlsEvent),
}

pub struct TlsConnection {
    inner: UnbufferedClientConnection,
    incoming: Vec<u8>,
    pending_transmit: Vec<u8>,
    hostname: String,
    state: TlsState,
}

impl TlsConnection {
    pub fn new(config: Arc<ClientConfig>, hostname: &str) -> Result<Self, TlsError> {
        let hostname = normalize_dns_name(hostname)?;
        let server_name = match ServerName::try_from(hostname.clone()) {
            Ok(ServerName::DnsName(name)) => ServerName::DnsName(name),
            _ => return Err(TlsError::InvalidServerName),
        };
        let inner = UnbufferedClientConnection::new(config, server_name)
            .map_err(|error| TlsError::from_rustls(&error))?;
        Ok(Self {
            inner,
            incoming: Vec::new(),
            pending_transmit: Vec::new(),
            hostname,
            state: TlsState::Handshaking,
        })
    }

    pub fn server_hostname(&self) -> &str {
        &self.hostname
    }

    pub const fn state(&self) -> TlsState {
        self.state
    }

    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.inner.protocol_version()
    }

    pub fn cipher_suite(&self) -> Option<CipherSuite> {
        self.inner
            .negotiated_cipher_suite()
            .map(|suite| suite.suite())
    }

    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.inner.peer_certificates()
    }

    pub fn peer_certificate_info(&self) -> Result<PeerCertificateInfo, TlsError> {
        if self.state != TlsState::Established {
            return Err(TlsError::InvalidState);
        }
        let end_entity = self
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or(TlsError::CertificateInvalid)?;
        let certificate =
            Certificate::from_der(end_entity.as_ref()).map_err(|_| TlsError::CertificateInvalid)?;
        let subject = certificate.tbs_certificate.subject.to_string();
        let issuer = certificate.tbs_certificate.issuer.to_string();
        if subject.len() > MAX_PEER_CERTIFICATE_NAME_LEN
            || issuer.len() > MAX_PEER_CERTIFICATE_NAME_LEN
        {
            return Err(TlsError::BufferLimit);
        }
        Ok(PeerCertificateInfo {
            subject,
            issuer,
            not_before: certificate
                .tbs_certificate
                .validity
                .not_before
                .to_unix_duration()
                .as_secs(),
            not_after: certificate
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs(),
        })
    }

    pub fn receive_tls(&mut self, bytes: &[u8]) -> Result<(), TlsError> {
        if matches!(self.state, TlsState::Closed | TlsState::Failed) {
            return Err(TlsError::InvalidState);
        }
        if self.incoming.len().saturating_add(bytes.len()) > MAX_TLS_HANDSHAKE_BUFFER {
            self.state = TlsState::Failed;
            return Err(TlsError::BufferLimit);
        }
        self.incoming.extend_from_slice(bytes);
        Ok(())
    }

    pub fn next_event(&mut self) -> Result<TlsEvent, TlsError> {
        if self.state == TlsState::Failed {
            return Err(TlsError::InvalidState);
        }
        loop {
            let mut discard;
            let step = {
                let status = self.inner.process_tls_records(&mut self.incoming);
                discard = status.discard;
                let state = match status.state {
                    Ok(state) => state,
                    Err(error) => {
                        self.state = TlsState::Failed;
                        return Err(TlsError::from_rustls(&error));
                    }
                };
                match state {
                    ConnectionState::EncodeTlsData(mut encoder) => {
                        let mut output = vec![0u8; MAX_TLS_RECORD];
                        let length = encoder.encode(&mut output).map_err(map_encode_error)?;
                        output.truncate(length);
                        self.pending_transmit.extend_from_slice(&output);
                        Step::Continue
                    }
                    ConnectionState::TransmitTlsData(transmit) => {
                        transmit.done();
                        if self.pending_transmit.is_empty() {
                            self.state = TlsState::Failed;
                            return Err(TlsError::InvalidState);
                        }
                        Step::Event(TlsEvent::Transmit(core::mem::take(
                            &mut self.pending_transmit,
                        )))
                    }
                    ConnectionState::BlockedHandshake => Step::Event(TlsEvent::NeedReceive),
                    ConnectionState::WriteTraffic(_) => {
                        if self.state == TlsState::Handshaking {
                            self.state = TlsState::Established;
                            Step::Event(TlsEvent::Established)
                        } else {
                            Step::Event(TlsEvent::NeedReceive)
                        }
                    }
                    ConnectionState::ReadTraffic(mut traffic) => {
                        let mut plaintext = Vec::new();
                        while let Some(record) = traffic.next_record() {
                            let record = record.map_err(|error| TlsError::from_rustls(&error))?;
                            discard = discard
                                .checked_add(record.discard)
                                .ok_or(TlsError::BufferLimit)?;
                            if plaintext.len().saturating_add(record.payload.len())
                                > MAX_TLS_PLAINTEXT
                            {
                                self.state = TlsState::Failed;
                                return Err(TlsError::BufferLimit);
                            }
                            plaintext.extend_from_slice(record.payload);
                        }
                        if plaintext.is_empty() {
                            Step::Continue
                        } else {
                            Step::Event(TlsEvent::Plaintext(plaintext))
                        }
                    }
                    ConnectionState::PeerClosed => {
                        self.state = TlsState::PeerClosed;
                        Step::Event(TlsEvent::PeerClosed)
                    }
                    ConnectionState::Closed => {
                        self.state = TlsState::Closed;
                        Step::Event(TlsEvent::Closed)
                    }
                    ConnectionState::ReadEarlyData(_) => {
                        self.state = TlsState::Failed;
                        return Err(TlsError::Protocol);
                    }
                    _ => {
                        self.state = TlsState::Failed;
                        return Err(TlsError::Protocol);
                    }
                }
            };
            self.discard_incoming(discard)?;
            match step {
                Step::Continue => {}
                Step::Event(event) => return Ok(event),
            }
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, TlsError> {
        if self.state != TlsState::Established || plaintext.len() > MAX_TLS_PLAINTEXT {
            return Err(if plaintext.len() > MAX_TLS_PLAINTEXT {
                TlsError::BufferLimit
            } else {
                TlsError::InvalidState
            });
        }
        let mut output = vec![0u8; MAX_TLS_RECORD];
        let discard;
        let length = {
            let status = self.inner.process_tls_records(&mut self.incoming);
            discard = status.discard;
            match status.state {
                Ok(ConnectionState::WriteTraffic(mut traffic)) => traffic
                    .encrypt(plaintext, &mut output)
                    .map_err(map_encrypt_error)?,
                Ok(_) => return Err(TlsError::InvalidState),
                Err(error) => {
                    self.state = TlsState::Failed;
                    return Err(TlsError::from_rustls(&error));
                }
            }
        };
        self.discard_incoming(discard)?;
        output.truncate(length);
        Ok(output)
    }

    pub fn close_notify(&mut self) -> Result<Vec<u8>, TlsError> {
        if !matches!(self.state, TlsState::Established | TlsState::PeerClosed) {
            return Err(TlsError::InvalidState);
        }
        loop {
            let mut output = vec![0u8; MAX_TLS_RECORD];
            let discard;
            let mut peer_closed = false;
            let length = {
                let status = self.inner.process_tls_records(&mut self.incoming);
                discard = status.discard;
                match status.state {
                    Ok(ConnectionState::WriteTraffic(mut traffic)) => Some(
                        traffic
                            .queue_close_notify(&mut output)
                            .map_err(map_encrypt_error)?,
                    ),
                    Ok(ConnectionState::PeerClosed) => {
                        peer_closed = true;
                        None
                    }
                    Ok(_) => return Err(TlsError::InvalidState),
                    Err(error) => {
                        self.state = TlsState::Failed;
                        return Err(TlsError::from_rustls(&error));
                    }
                }
            };
            self.discard_incoming(discard)?;
            if peer_closed {
                self.state = TlsState::PeerClosed;
                continue;
            }
            let length = length.ok_or(TlsError::InvalidState)?;
            self.state = TlsState::Closing;
            output.truncate(length);
            return Ok(output);
        }
    }

    fn discard_incoming(&mut self, count: usize) -> Result<(), TlsError> {
        if count > self.incoming.len() {
            self.state = TlsState::Failed;
            return Err(TlsError::Protocol);
        }
        self.incoming.drain(..count);
        Ok(())
    }
}

fn normalize_dns_name(hostname: &str) -> Result<String, TlsError> {
    let normalized = hostname.strip_suffix('.').unwrap_or(hostname);
    if normalized.is_empty()
        || normalized.len() > MAX_TLS_HOSTNAME_LEN
        || normalized.as_bytes().contains(&0)
        || normalized.contains('*')
    {
        return Err(TlsError::InvalidServerName);
    }
    Ok(normalized.to_ascii_lowercase())
}

fn map_encode_error(error: EncodeError) -> TlsError {
    match error {
        EncodeError::InsufficientSize(_) => TlsError::BufferLimit,
        EncodeError::AlreadyEncoded => TlsError::InvalidState,
    }
}

fn map_encrypt_error(error: EncryptError) -> TlsError {
    match error {
        EncryptError::InsufficientSize(_) => TlsError::BufferLimit,
        EncryptError::EncryptExhausted => TlsError::Protocol,
    }
}
