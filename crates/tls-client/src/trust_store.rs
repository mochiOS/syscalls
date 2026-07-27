use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
#[cfg(feature = "test-web-pki")]
use rustls::pki_types::pem::PemObject;

use crate::TlsError;

pub const WEB_PKI_ROOTS_VERSION: &str = "webpki-roots 1.0.9";
pub const WEB_PKI_ROOTS_COUNT: usize = 121;

pub fn production_root_store() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

#[cfg(feature = "test-web-pki")]
pub fn smoke_test_root_store() -> Result<RootCertStore, TlsError> {
    let certificate =
        CertificateDer::from_pem_slice(include_bytes!("../test-fixtures/test-root.cert.pem"))
            .map_err(|_| TlsError::CertificateInvalid)?;
    root_store_from_der(&[certificate.as_ref()])
}

pub fn root_store_from_der(certificates: &[&[u8]]) -> Result<RootCertStore, TlsError> {
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        if certificate.len() > crate::MAX_CERTIFICATE_SIZE {
            return Err(TlsError::CertificateTooLarge);
        }
        roots
            .add(CertificateDer::from(*certificate))
            .map_err(|_| TlsError::CertificateInvalid)?;
    }
    if roots.is_empty() {
        return Err(TlsError::CertificateInvalid);
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_root_bundle_identity_is_fixed() {
        assert_eq!(WEB_PKI_ROOTS_VERSION, "webpki-roots 1.0.9");
        assert_eq!(webpki_roots::TLS_SERVER_ROOTS.len(), WEB_PKI_ROOTS_COUNT);
        assert_eq!(production_root_store().len(), WEB_PKI_ROOTS_COUNT);
    }
}
