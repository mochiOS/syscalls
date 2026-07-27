use alloc::sync::Arc;

use rustls::client::{ClientConfig, Resumption, WebPkiServerVerifier};
use rustls::time_provider::TimeProvider;
use rustls::{CipherSuite, NamedGroup, RootCertStore};

use crate::TlsError;
use crate::verifier::BoundedWebPkiVerifier;

pub fn crypto_provider() -> rustls::crypto::CryptoProvider {
    let mut provider = rustls_rustcrypto::provider();
    provider.cipher_suites.retain(|suite| {
        matches!(
            suite.suite(),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 | CipherSuite::TLS13_AES_128_GCM_SHA256
        )
    });
    provider
        .cipher_suites
        .sort_by_key(|suite| match suite.suite() {
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 0,
            CipherSuite::TLS13_AES_128_GCM_SHA256 => 1,
            _ => 2,
        });
    provider
        .kx_groups
        .retain(|group| group.name() == NamedGroup::X25519);
    provider
}

pub fn build_client_config(
    roots: RootCertStore,
    time_provider: Arc<dyn TimeProvider>,
) -> Result<ClientConfig, TlsError> {
    let provider = Arc::new(crypto_provider());
    if provider.cipher_suites.len() != 2 || provider.kx_groups.len() != 1 {
        return Err(TlsError::InvalidConfiguration);
    }
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|_| TlsError::InvalidConfiguration)?;
    let mut config = ClientConfig::builder_with_details(provider, time_provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| TlsError::InvalidConfiguration)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(BoundedWebPkiVerifier::new(verifier)))
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.enable_sni = true;
    config.enable_early_data = false;
    config.enable_secret_extraction = false;
    config.alpn_protocols.clear();
    Ok(config)
}
