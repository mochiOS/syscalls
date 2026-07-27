#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod config;
mod connection;
mod error;
mod time;
mod trust_store;
mod verifier;

#[cfg(test)]
mod integration_tests;

pub use config::{build_client_config, crypto_provider};
pub use connection::{PeerCertificateInfo, TlsConnection, TlsEvent, TlsState};
pub use error::TlsError;
pub use time::FixedTimeProvider;
#[cfg(any(target_os = "mochios", target_os = "none"))]
pub use time::PlatformTimeProvider;
#[cfg(feature = "test-web-pki")]
pub use trust_store::smoke_test_root_store;
pub use trust_store::{
    WEB_PKI_ROOTS_COUNT, WEB_PKI_ROOTS_VERSION, production_root_store, root_store_from_der,
};

pub use rustls;

pub const MAX_CERTIFICATE_CHAIN_DEPTH: usize = 8;
pub const MAX_CERTIFICATE_SIZE: usize = 64 * 1024;
pub const MAX_CERTIFICATE_CHAIN_BYTES: usize = 64 * 1024;
pub const MAX_TLS_CONNECTIONS: usize = 16;
pub const MAX_TLS_PLAINTEXT: usize = 16 * 1024;
pub const MAX_TLS_RECORD: usize = 16 * 1024 + 2 * 1024 + 5;
pub const MAX_TLS_HANDSHAKE_BUFFER: usize = 64 * 1024;
pub const MAX_TLS_HOSTNAME_LEN: usize = 253;
pub const MAX_PEER_CERTIFICATE_NAME_LEN: usize = 512;

#[cfg(any(target_os = "mochios", target_os = "none"))]
pub fn platform_getrandom(destination: &mut [u8]) -> Result<(), getrandom::Error> {
    mochi_user_platform::random::fill(destination).map_err(|_| getrandom::Error::UNEXPECTED)
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::*;

    #[test]
    fn provider_is_limited_to_tls_1_3_x25519_and_required_suites() {
        let provider = crypto_provider();
        let suites = provider
            .cipher_suites
            .iter()
            .map(|suite| suite.suite())
            .collect::<alloc::vec::Vec<_>>();
        assert_eq!(
            suites,
            [
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            ]
        );
        assert!(
            provider
                .cipher_suites
                .iter()
                .all(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(provider.kx_groups.len(), 1);
        assert_eq!(provider.kx_groups[0].name(), rustls::NamedGroup::X25519);
        assert!(
            provider
                .signature_verification_algorithms
                .supported_schemes()
                .iter()
                .all(|scheme| !matches!(
                    scheme,
                    rustls::SignatureScheme::RSA_PKCS1_SHA1
                        | rustls::SignatureScheme::ECDSA_SHA1_Legacy
                ))
        );
    }

    #[test]
    fn tls_connection_limit_is_fixed() {
        assert_eq!(MAX_TLS_CONNECTIONS, 16);
    }

    #[test]
    fn fixed_time_provider_can_fail_closed() {
        use rustls::time_provider::TimeProvider;

        assert_eq!(FixedTimeProvider::unavailable().current_time(), None);
        assert_eq!(
            FixedTimeProvider::at(1_700_000_000).current_time(),
            Some(rustls::pki_types::UnixTime::since_unix_epoch(
                core::time::Duration::from_secs(1_700_000_000)
            ))
        );
    }

    #[test]
    fn production_configuration_is_tls_1_3_only() {
        let roots = production_root_store();
        assert!(!roots.is_empty());
        let Ok(config) = build_client_config(roots, Arc::new(FixedTimeProvider::at(1_700_000_000)))
        else {
            panic!("built-in TLS configuration must be valid");
        };
        assert!(config.enable_sni);
        assert!(!config.enable_early_data);
        assert!(!config.enable_secret_extraction);
    }

    #[test]
    fn client_hello_contains_sni_and_uses_tls_record_bounds() {
        let Ok(config) = build_client_config(
            production_root_store(),
            Arc::new(FixedTimeProvider::at(1_700_000_000)),
        ) else {
            panic!("built-in TLS configuration must be valid");
        };
        let Ok(mut connection) = TlsConnection::new(Arc::new(config), "Example.COM.") else {
            panic!("valid DNS name must create a TLS connection");
        };
        assert_eq!(connection.server_hostname(), "example.com");
        let Ok(TlsEvent::Transmit(client_hello)) = connection.next_event() else {
            panic!("new connection must emit ClientHello");
        };
        assert!(client_hello.len() <= MAX_TLS_RECORD);
        assert_eq!(client_hello.first(), Some(&22));
        assert!(
            client_hello
                .windows(b"example.com".len())
                .any(|window| window == b"example.com")
        );
    }

    #[test]
    fn server_name_rejects_ip_wildcard_and_empty_names() {
        let Ok(config) = build_client_config(
            production_root_store(),
            Arc::new(FixedTimeProvider::at(1_700_000_000)),
        ) else {
            panic!("built-in TLS configuration must be valid");
        };
        let config = Arc::new(config);
        assert!(matches!(
            TlsConnection::new(config.clone(), "127.0.0.1"),
            Err(TlsError::InvalidServerName)
        ));
        assert!(matches!(
            TlsConnection::new(config.clone(), "*.example.com"),
            Err(TlsError::InvalidServerName)
        ));
        assert!(matches!(
            TlsConnection::new(config, ""),
            Err(TlsError::InvalidServerName)
        ));
    }
}
