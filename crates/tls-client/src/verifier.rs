use alloc::sync::Arc;
use alloc::vec::Vec;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme};
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::ext::pkix::KeyUsage;

use crate::{MAX_CERTIFICATE_CHAIN_BYTES, MAX_CERTIFICATE_CHAIN_DEPTH, MAX_CERTIFICATE_SIZE};

pub(crate) const CHAIN_DEPTH_LIMIT_ERROR: &str = "mochiOS certificate chain depth limit exceeded";
pub(crate) const CERTIFICATE_SIZE_LIMIT_ERROR: &str = "mochiOS certificate size limit exceeded";
pub(crate) const CHAIN_BYTES_LIMIT_ERROR: &str = "mochiOS certificate chain byte limit exceeded";

#[derive(Debug)]
pub(crate) struct BoundedWebPkiVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl BoundedWebPkiVerifier {
    pub(crate) const fn new(inner: Arc<WebPkiServerVerifier>) -> Self {
        Self { inner }
    }
}

impl ServerCertVerifier for BoundedWebPkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        validate_chain_bounds(end_entity, intermediates)?;
        validate_leaf_key_usage(end_entity)?;
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

fn validate_leaf_key_usage(end_entity: &CertificateDer<'_>) -> Result<(), Error> {
    let certificate = Certificate::from_der(end_entity.as_ref())
        .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
    let key_usage = certificate
        .tbs_certificate
        .get::<KeyUsage>()
        .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;
    if key_usage.is_some_and(|(_, usage)| !usage.digital_signature()) {
        return Err(Error::InvalidCertificate(CertificateError::InvalidPurpose));
    }
    Ok(())
}

fn validate_chain_bounds(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> Result<(), Error> {
    if intermediates.len().saturating_add(1) > MAX_CERTIFICATE_CHAIN_DEPTH {
        return Err(Error::General(CHAIN_DEPTH_LIMIT_ERROR.into()));
    }
    if end_entity.len() > MAX_CERTIFICATE_SIZE
        || intermediates
            .iter()
            .any(|certificate| certificate.len() > MAX_CERTIFICATE_SIZE)
    {
        return Err(Error::General(CERTIFICATE_SIZE_LIMIT_ERROR.into()));
    }
    let chain_bytes = intermediates
        .iter()
        .try_fold(end_entity.len(), |total, certificate| {
            total.checked_add(certificate.len())
        })
        .ok_or_else(|| Error::General(CHAIN_BYTES_LIMIT_ERROR.into()))?;
    if chain_bytes > MAX_CERTIFICATE_CHAIN_BYTES {
        return Err(Error::General(CHAIN_BYTES_LIMIT_ERROR.into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn certificate_chain_bounds_are_enforced_before_parsing() {
        let certificate = CertificateDer::from(&b"certificate"[..]);
        assert_eq!(validate_chain_bounds(&certificate, &[]), Ok(()));

        let intermediates = vec![certificate.clone(); MAX_CERTIFICATE_CHAIN_DEPTH];
        assert!(matches!(
            validate_chain_bounds(&certificate, &intermediates),
            Err(Error::General(message)) if message == CHAIN_DEPTH_LIMIT_ERROR
        ));

        let oversized = vec![0u8; MAX_CERTIFICATE_SIZE + 1];
        let oversized = CertificateDer::from(oversized);
        assert!(matches!(
            validate_chain_bounds(&oversized, &[]),
            Err(Error::General(message)) if message == CERTIFICATE_SIZE_LIMIT_ERROR
        ));

        let half = vec![0u8; MAX_CERTIFICATE_CHAIN_BYTES / 2 + 1];
        let intermediate = CertificateDer::from(half.clone());
        let leaf = CertificateDer::from(half);
        assert!(matches!(
            validate_chain_bounds(&leaf, &[intermediate]),
            Err(Error::General(message)) if message == CHAIN_BYTES_LIMIT_ERROR
        ));
    }
}
