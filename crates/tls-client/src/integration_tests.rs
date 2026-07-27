use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use std::io::{Cursor, Read, Write};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertifiedIssuer, CustomExtension, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, date_time_ymd,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};

use crate::{
    FixedTimeProvider, TlsConnection, TlsError, TlsEvent, TlsState, build_client_config,
    crypto_provider, root_store_from_der,
};

const VALID_TIME: u64 = 1_700_000_000;

struct TestIdentity {
    root: Certificate,
    leaf: Certificate,
    leaf_key: KeyPair,
}

fn test_identity(hostname: &str) -> TestIdentity {
    test_identity_with(hostname, |_| {})
}

fn test_identity_with(
    hostname: &str,
    customize: impl FnOnce(&mut CertificateParams),
) -> TestIdentity {
    let Ok(mut root_params) = CertificateParams::new(Vec::new()) else {
        panic!("empty CA subject alternative name list must be valid");
    };
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    root_params.not_before = date_time_ymd(2020, 1, 1);
    root_params.not_after = date_time_ymd(2030, 1, 1);
    let Ok(root_key) = KeyPair::generate() else {
        panic!("test CA key generation must succeed");
    };
    let Ok(root) = root_params.self_signed(&root_key) else {
        panic!("test CA certificate generation must succeed");
    };
    let issuer = Issuer::new(root_params, root_key);

    let Ok(mut leaf_params) = CertificateParams::new(vec![hostname.into()]) else {
        panic!("test server hostname must be valid");
    };
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, hostname);
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.not_before = date_time_ymd(2021, 1, 1);
    leaf_params.not_after = date_time_ymd(2029, 1, 1);
    customize(&mut leaf_params);
    let Ok(leaf_key) = KeyPair::generate() else {
        panic!("test server key generation must succeed");
    };
    let Ok(leaf) = leaf_params.signed_by(&leaf_key, &issuer) else {
        panic!("test server certificate generation must succeed");
    };
    TestIdentity {
        root,
        leaf,
        leaf_key,
    }
}

fn client_for(identity: &TestIdentity, hostname: &str, now: u64) -> TlsConnection {
    let Ok(roots) = root_store_from_der(&[identity.root.der().as_ref()]) else {
        panic!("test CA must load into the root store");
    };
    let Ok(config) = build_client_config(roots, Arc::new(FixedTimeProvider::at(now))) else {
        panic!("test client configuration must be valid");
    };
    let Ok(connection) = TlsConnection::new(Arc::new(config), hostname) else {
        panic!("test hostname must create a client connection");
    };
    connection
}

fn server_for(identity: &TestIdentity) -> ServerConnection {
    server_for_certificate(identity, identity.leaf.der().to_vec())
}

fn server_for_certificate(identity: &TestIdentity, certificate: Vec<u8>) -> ServerConnection {
    server_for_chain(identity, vec![CertificateDer::from(certificate)])
}

fn server_for_chain(
    identity: &TestIdentity,
    certificates: Vec<CertificateDer<'static>>,
) -> ServerConnection {
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(identity.leaf_key.serialize_der()));
    server_for_der_chain(certificates, key)
}

fn server_for_der_chain(
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> ServerConnection {
    let provider = Arc::new(crypto_provider());
    let builder =
        ServerConfig::builder_with_details(provider, Arc::new(FixedTimeProvider::at(VALID_TIME)));
    let Ok(builder) = builder.with_protocol_versions(&[&rustls::version::TLS13]) else {
        panic!("test server must support TLS 1.3");
    };
    let Ok(mut config) = builder
        .with_no_client_auth()
        .with_single_cert(certificates, key)
    else {
        panic!("test server certificate and key must be usable");
    };
    config.send_tls13_tickets = 0;
    let Ok(server) = ServerConnection::new(Arc::new(config)) else {
        panic!("test server connection must initialize");
    };
    server
}

fn tls_1_2_server_for(identity: &TestIdentity) -> ServerConnection {
    let provider = Arc::new(rustls_rustcrypto::provider());
    let builder =
        ServerConfig::builder_with_details(provider, Arc::new(FixedTimeProvider::at(VALID_TIME)));
    let Ok(builder) = builder.with_protocol_versions(&[&rustls::version::TLS12]) else {
        panic!("test server must support TLS 1.2");
    };
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(identity.leaf_key.serialize_der()));
    let certificates = vec![CertificateDer::from(identity.leaf.der().to_vec())];
    let Ok(config) = builder
        .with_no_client_auth()
        .with_single_cert(certificates, key)
    else {
        panic!("test server certificate and key must be usable");
    };
    let Ok(server) = ServerConnection::new(Arc::new(config)) else {
        panic!("test TLS 1.2 server connection must initialize");
    };
    server
}

fn path_length_violating_chain() -> (
    Certificate,
    Vec<CertificateDer<'static>>,
    Certificate,
    KeyPair,
) {
    let Ok(mut root_params) = CertificateParams::new(Vec::new()) else {
        panic!("empty CA subject alternative name list must be valid");
    };
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    root_params.not_before = date_time_ymd(2020, 1, 1);
    root_params.not_after = date_time_ymd(2030, 1, 1);
    let Ok(root_key) = KeyPair::generate() else {
        panic!("test root key generation must succeed");
    };
    let Ok(root) = CertifiedIssuer::self_signed(root_params, root_key) else {
        panic!("test root certificate generation must succeed");
    };

    let Ok(mut intermediate_params) = CertificateParams::new(Vec::new()) else {
        panic!("empty intermediate subject alternative name list must be valid");
    };
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    intermediate_params.not_before = date_time_ymd(2020, 1, 1);
    intermediate_params.not_after = date_time_ymd(2030, 1, 1);
    let Ok(intermediate_key) = KeyPair::generate() else {
        panic!("test intermediate key generation must succeed");
    };
    let Ok(intermediate) = CertifiedIssuer::signed_by(intermediate_params, intermediate_key, &root)
    else {
        panic!("test intermediate certificate generation must succeed");
    };

    let Ok(mut subordinate_params) = CertificateParams::new(Vec::new()) else {
        panic!("empty subordinate CA subject alternative name list must be valid");
    };
    subordinate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    subordinate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    subordinate_params.not_before = date_time_ymd(2020, 1, 1);
    subordinate_params.not_after = date_time_ymd(2030, 1, 1);
    let Ok(subordinate_key) = KeyPair::generate() else {
        panic!("test subordinate CA key generation must succeed");
    };
    let Ok(subordinate) =
        CertifiedIssuer::signed_by(subordinate_params, subordinate_key, &intermediate)
    else {
        panic!("test subordinate CA certificate generation must succeed");
    };

    let Ok(mut leaf_params) = CertificateParams::new(vec!["localhost".into()]) else {
        panic!("test server hostname must be valid");
    };
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.not_before = date_time_ymd(2021, 1, 1);
    leaf_params.not_after = date_time_ymd(2029, 1, 1);
    let Ok(leaf_key) = KeyPair::generate() else {
        panic!("test leaf key generation must succeed");
    };
    let Ok(leaf) = leaf_params.signed_by(&leaf_key, &subordinate) else {
        panic!("test leaf certificate generation must succeed");
    };
    (
        root.as_ref().clone(),
        vec![
            CertificateDer::from(leaf.der().to_vec()),
            CertificateDer::from(subordinate.der().to_vec()),
            CertificateDer::from(intermediate.der().to_vec()),
        ],
        leaf,
        leaf_key,
    )
}

fn receive_at_server(server: &mut ServerConnection, bytes: &[u8]) -> Result<(), rustls::Error> {
    let mut cursor = Cursor::new(bytes);
    while cursor.position() < bytes.len() as u64 {
        if server
            .read_tls(&mut cursor)
            .map_err(|_| rustls::Error::General("test I/O".into()))?
            == 0
        {
            return Err(rustls::Error::General("truncated test TLS input".into()));
        }
    }
    server.process_new_packets().map(|_| ())
}

fn transmit_from_server(server: &mut ServerConnection) -> Vec<u8> {
    let mut output = Vec::new();
    while server.wants_write() {
        let Ok(written) = server.write_tls(&mut output) else {
            panic!("writing test TLS records must succeed");
        };
        if written == 0 {
            break;
        }
    }
    output
}

fn establish(client: &mut TlsConnection, server: &mut ServerConnection) -> Result<(), TlsError> {
    for _ in 0..32 {
        match client.next_event()? {
            TlsEvent::Transmit(bytes) => {
                receive_at_server(server, &bytes).map_err(|_| TlsError::Protocol)?;
                let response = transmit_from_server(server);
                if !response.is_empty() {
                    client.receive_tls(&response)?;
                }
            }
            TlsEvent::NeedReceive => {
                let response = transmit_from_server(server);
                if response.is_empty() {
                    return Err(TlsError::Protocol);
                }
                client.receive_tls(&response)?;
            }
            TlsEvent::Established => return Ok(()),
            _ => return Err(TlsError::Protocol),
        }
    }
    Err(TlsError::Protocol)
}

fn establish_with_fragmented_input(
    client: &mut TlsConnection,
    server: &mut ServerConnection,
) -> Result<(), TlsError> {
    for _ in 0..64 {
        match client.next_event()? {
            TlsEvent::Transmit(bytes) => {
                receive_at_server(server, &bytes).map_err(|_| TlsError::Protocol)?;
                for byte in transmit_from_server(server) {
                    client.receive_tls(core::slice::from_ref(&byte))?;
                }
            }
            TlsEvent::NeedReceive => {
                let response = transmit_from_server(server);
                if response.is_empty() {
                    return Err(TlsError::Protocol);
                }
                for byte in response {
                    client.receive_tls(core::slice::from_ref(&byte))?;
                }
            }
            TlsEvent::Established => return Ok(()),
            _ => return Err(TlsError::Protocol),
        }
    }
    Err(TlsError::Protocol)
}

#[test]
fn complete_tls_1_3_exchange_and_close_notify() {
    let identity = test_identity("localhost");
    let mut client = client_for(&identity, "LOCALHOST.", VALID_TIME);
    let mut server = server_for(&identity);
    assert_eq!(establish(&mut client, &mut server), Ok(()));
    assert_eq!(client.state(), TlsState::Established);
    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert!(matches!(
        client.cipher_suite(),
        Some(
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                | rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
        )
    ));
    assert_eq!(client.peer_certificates().map(<[_]>::len), Some(1));
    let Ok(peer) = client.peer_certificate_info() else {
        panic!("established connection must expose verified peer metadata");
    };
    assert!(peer.subject.contains("localhost"));
    assert!(peer.issuer.contains("rcgen self signed cert"));
    assert!(peer.not_before <= VALID_TIME && peer.not_after >= VALID_TIME);

    let request = b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let Ok(encrypted_request) = client.encrypt(request) else {
        panic!("established client must encrypt application data");
    };
    assert_eq!(receive_at_server(&mut server, &encrypted_request), Ok(()));
    let mut received_request = vec![0u8; request.len()];
    let Ok(received) = server.reader().read(&mut received_request) else {
        panic!("test server must read application data");
    };
    received_request.truncate(received);
    assert_eq!(received_request, request);

    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
    let Ok(()) = server.writer().write_all(response) else {
        panic!("test server must write application data");
    };
    let encrypted_response = transmit_from_server(&mut server);
    assert!(!encrypted_response.is_empty());
    assert_eq!(client.receive_tls(&encrypted_response), Ok(()));
    assert_eq!(
        client.next_event(),
        Ok(TlsEvent::Plaintext(response.to_vec()))
    );

    let Ok(close) = client.close_notify() else {
        panic!("established client must send close_notify");
    };
    assert_eq!(receive_at_server(&mut server, &close), Ok(()));
    server.send_close_notify();
    let peer_close = transmit_from_server(&mut server);
    assert!(!peer_close.is_empty());
    assert_eq!(client.receive_tls(&peer_close), Ok(()));
    assert_eq!(client.next_event(), Ok(TlsEvent::PeerClosed));
}

#[test]
fn close_notify_handles_peer_close_already_buffered() {
    let identity = test_identity("localhost");
    let mut client = client_for(&identity, "localhost", VALID_TIME);
    let mut server = server_for(&identity);
    assert_eq!(establish(&mut client, &mut server), Ok(()));

    server.send_close_notify();
    let peer_close = transmit_from_server(&mut server);
    assert!(!peer_close.is_empty());
    assert_eq!(client.receive_tls(&peer_close), Ok(()));

    let Ok(close) = client.close_notify() else {
        panic!("client must acknowledge an already buffered peer close_notify");
    };
    assert!(!close.is_empty());
    assert_eq!(receive_at_server(&mut server, &close), Ok(()));
    assert_eq!(client.state(), TlsState::Closing);
}

#[test]
fn hostname_mismatch_is_rejected() {
    let identity = test_identity("localhost");
    let mut client = client_for(&identity, "other.example", VALID_TIME);
    let mut server = server_for(&identity);
    assert_eq!(
        establish(&mut client, &mut server),
        Err(TlsError::HostnameMismatch)
    );
    assert_eq!(client.state(), TlsState::Failed);
}

#[test]
fn untrusted_root_is_rejected() {
    let identity = test_identity("localhost");
    let untrusted = test_identity("untrusted.example");
    let mut client = client_for(&untrusted, "localhost", VALID_TIME);
    let mut server = server_for(&identity);
    assert_eq!(
        establish(&mut client, &mut server),
        Err(TlsError::CertificateInvalid)
    );
    assert_eq!(client.state(), TlsState::Failed);
}

#[test]
fn expired_certificate_is_rejected() {
    let identity = test_identity("localhost");
    let mut client = client_for(&identity, "localhost", 1_900_000_000);
    let mut server = server_for(&identity);
    assert_eq!(
        establish(&mut client, &mut server),
        Err(TlsError::CertificateInvalid)
    );
    assert_eq!(client.state(), TlsState::Failed);
}

#[test]
fn not_yet_valid_certificate_is_rejected() {
    let identity = test_identity("localhost");
    let mut client = client_for(&identity, "localhost", 1_500_000_000);
    let mut server = server_for(&identity);
    assert_eq!(
        establish(&mut client, &mut server),
        Err(TlsError::CertificateInvalid)
    );
    assert_eq!(client.state(), TlsState::Failed);
}

#[test]
fn fragmented_handshake_input_is_reassembled() {
    let identity = test_identity("localhost");
    let mut client = client_for(&identity, "localhost", VALID_TIME);
    let mut server = server_for(&identity);
    assert_eq!(
        establish_with_fragmented_input(&mut client, &mut server),
        Ok(())
    );
    assert_eq!(client.state(), TlsState::Established);
}

#[test]
fn tls_1_2_only_peer_has_no_common_version() {
    let identity = test_identity("localhost");
    let mut client = client_for(&identity, "localhost", VALID_TIME);
    let mut server = tls_1_2_server_for(&identity);
    let Ok(TlsEvent::Transmit(client_hello)) = client.next_event() else {
        panic!("new client must transmit ClientHello");
    };
    assert!(receive_at_server(&mut server, &client_hello).is_err());
    assert_eq!(client.state(), TlsState::Handshaking);
}

#[test]
fn wildcard_san_matches_only_one_leftmost_label() {
    let identity = test_identity("*.example.com");
    let mut client = client_for(&identity, "api.example.com", VALID_TIME);
    let mut server = server_for(&identity);
    assert_eq!(establish(&mut client, &mut server), Ok(()));

    for hostname in ["example.com", "deep.api.example.com"] {
        let mut client = client_for(&identity, hostname, VALID_TIME);
        let mut server = server_for(&identity);
        assert_eq!(
            establish(&mut client, &mut server),
            Err(TlsError::HostnameMismatch)
        );
    }
}

#[test]
fn invalid_wildcard_san_forms_are_rejected() {
    for (pattern, hostname) in [
        ("*.com", "example.com"),
        ("*.*.example.com", "a.b.example.com"),
        ("foo*.example.com", "foobar.example.com"),
        ("example.*", "example.com"),
    ] {
        let identity = test_identity(pattern);
        let mut client = client_for(&identity, hostname, VALID_TIME);
        let mut server = server_for(&identity);
        assert!(matches!(
            establish(&mut client, &mut server),
            Err(TlsError::HostnameMismatch | TlsError::CertificateInvalid)
        ));
        assert_eq!(client.state(), TlsState::Failed);
    }
}

#[test]
fn invalid_certificate_signature_is_rejected() {
    let identity = test_identity("localhost");
    let mut corrupted = identity.leaf.der().to_vec();
    let Some(last) = corrupted.last_mut() else {
        panic!("test certificate DER must not be empty");
    };
    *last ^= 1;
    let mut client = client_for(&identity, "localhost", VALID_TIME);
    let mut server = server_for_certificate(&identity, corrupted);
    assert_eq!(
        establish(&mut client, &mut server),
        Err(TlsError::CertificateInvalid)
    );
}

#[test]
fn unknown_critical_certificate_extension_is_rejected() {
    let identity = test_identity_with("localhost", |params| {
        let mut extension =
            CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 55555, 1], vec![0x05, 0x00]);
        extension.set_criticality(true);
        params.custom_extensions.push(extension);
    });
    let mut client = client_for(&identity, "localhost", VALID_TIME);
    let mut server = server_for(&identity);
    assert_eq!(
        establish(&mut client, &mut server),
        Err(TlsError::CertificateInvalid)
    );
}

#[test]
fn ca_certificate_cannot_be_used_as_server_leaf() {
    let identity = test_identity_with("localhost", |params| {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    });
    let mut client = client_for(&identity, "localhost", VALID_TIME);
    let mut server = server_for(&identity);
    assert_eq!(
        establish(&mut client, &mut server),
        Err(TlsError::CertificateInvalid)
    );
}

#[test]
fn unsuitable_key_usage_is_rejected() {
    let identity = test_identity_with("localhost", |params| {
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    });
    let mut client = client_for(&identity, "localhost", VALID_TIME);
    let mut server = server_for(&identity);
    assert_eq!(
        establish(&mut client, &mut server),
        Err(TlsError::CertificateInvalid)
    );
}

#[test]
fn missing_server_auth_extended_key_usage_is_rejected() {
    let identity = test_identity_with("localhost", |params| {
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    });
    let mut client = client_for(&identity, "localhost", VALID_TIME);
    let mut server = server_for(&identity);
    assert_eq!(
        establish(&mut client, &mut server),
        Err(TlsError::CertificateInvalid)
    );
}

#[test]
fn path_length_constraint_is_enforced() {
    let (root, chain, leaf, leaf_key) = path_length_violating_chain();
    let identity = TestIdentity {
        root,
        leaf,
        leaf_key,
    };
    let mut client = client_for(&identity, "localhost", VALID_TIME);
    let mut server = server_for_chain(&identity, chain);
    assert_eq!(
        establish(&mut client, &mut server),
        Err(TlsError::CertificateInvalid)
    );
}

#[test]
fn sha_1_signed_server_certificate_is_rejected() {
    let Ok(root) =
        CertificateDer::from_pem_slice(include_bytes!("../test-fixtures/sha1-root.cert.pem"))
    else {
        panic!("SHA-1 test root certificate must decode");
    };
    let Ok(leaf) =
        CertificateDer::from_pem_slice(include_bytes!("../test-fixtures/sha1-server.cert.pem"))
    else {
        panic!("SHA-1 test leaf certificate must decode");
    };
    let Ok(key) =
        PrivateKeyDer::from_pem_slice(include_bytes!("../test-fixtures/sha1-server.key.pem"))
    else {
        panic!("SHA-1 test server key must decode");
    };
    let Ok(roots) = root_store_from_der(&[root.as_ref()]) else {
        panic!("SHA-1 test root must load as a trust anchor");
    };
    let Ok(config) = build_client_config(roots, Arc::new(FixedTimeProvider::at(1_800_000_000)))
    else {
        panic!("test client configuration must be valid");
    };
    let Ok(mut client) = TlsConnection::new(Arc::new(config), "localhost") else {
        panic!("test hostname must create a client connection");
    };
    let mut server = server_for_der_chain(vec![leaf], key);
    assert_eq!(
        establish(&mut client, &mut server),
        Err(TlsError::CertificateInvalid)
    );
}

#[test]
fn unavailable_utc_time_fails_closed() {
    let identity = test_identity("localhost");
    let Ok(roots) = root_store_from_der(&[identity.root.der().as_ref()]) else {
        panic!("test CA must load into the root store");
    };
    let Ok(config) = build_client_config(roots, Arc::new(FixedTimeProvider::unavailable())) else {
        panic!("test client configuration must be valid");
    };
    let Ok(mut client) = TlsConnection::new(Arc::new(config), "localhost") else {
        panic!("test hostname must create a client connection");
    };
    let mut server = server_for(&identity);
    assert_eq!(
        establish(&mut client, &mut server),
        Err(TlsError::TimeUnavailable)
    );
}

#[test]
fn tampered_application_record_is_rejected() {
    let identity = test_identity("localhost");
    let mut client = client_for(&identity, "localhost", VALID_TIME);
    let mut server = server_for(&identity);
    assert_eq!(establish(&mut client, &mut server), Ok(()));

    let Ok(()) = server.writer().write_all(b"authenticated") else {
        panic!("test server must write application data");
    };
    let mut record = transmit_from_server(&mut server);
    let Some(last) = record.last_mut() else {
        panic!("application record must not be empty");
    };
    *last ^= 1;
    assert_eq!(client.receive_tls(&record), Ok(()));
    assert_eq!(client.next_event(), Err(TlsError::AuthenticationFailed));
    assert_eq!(client.state(), TlsState::Failed);
}

#[test]
fn tampered_encrypted_handshake_is_rejected_before_established() {
    let identity = test_identity("localhost");
    let mut client = client_for(&identity, "localhost", VALID_TIME);
    let mut server = server_for(&identity);
    let Ok(TlsEvent::Transmit(client_hello)) = client.next_event() else {
        panic!("new client must transmit ClientHello");
    };
    assert_eq!(receive_at_server(&mut server, &client_hello), Ok(()));
    let mut server_flight = transmit_from_server(&mut server);
    let Some(last) = server_flight.last_mut() else {
        panic!("server handshake flight must not be empty");
    };
    *last ^= 1;
    assert_eq!(client.receive_tls(&server_flight), Ok(()));
    assert!(matches!(
        client.next_event(),
        Err(TlsError::AuthenticationFailed | TlsError::Protocol)
    ));
    assert_eq!(client.state(), TlsState::Failed);
}

#[test]
fn fatal_alert_is_reported_and_closes_the_state_machine() {
    let identity = test_identity("localhost");
    let mut client = client_for(&identity, "localhost", VALID_TIME);
    assert!(matches!(client.next_event(), Ok(TlsEvent::Transmit(_))));
    assert_eq!(client.receive_tls(&[21, 3, 3, 0, 2, 2, 40]), Ok(()));
    assert_eq!(client.next_event(), Err(TlsError::PeerAlert));
    assert_eq!(client.state(), TlsState::Failed);
}

#[test]
fn tls_record_plaintext_and_handshake_buffers_are_bounded() {
    let identity = test_identity("localhost");
    let mut client = client_for(&identity, "localhost", VALID_TIME);
    let oversized = vec![0u8; crate::MAX_TLS_HANDSHAKE_BUFFER + 1];
    assert_eq!(client.receive_tls(&oversized), Err(TlsError::BufferLimit));
    assert_eq!(client.state(), TlsState::Failed);

    let mut client = client_for(&identity, "localhost", VALID_TIME);
    let mut server = server_for(&identity);
    assert_eq!(establish(&mut client, &mut server), Ok(()));
    let plaintext = vec![0u8; crate::MAX_TLS_PLAINTEXT + 1];
    assert_eq!(client.encrypt(&plaintext), Err(TlsError::BufferLimit));
}

#[test]
fn oversized_tls_record_header_is_rejected() {
    let identity = test_identity("localhost");
    let mut client = client_for(&identity, "localhost", VALID_TIME);
    assert!(matches!(client.next_event(), Ok(TlsEvent::Transmit(_))));
    assert_eq!(client.receive_tls(&[22, 3, 3, 0xff, 0xff]), Ok(()));
    assert!(matches!(
        client.next_event(),
        Err(TlsError::Protocol | TlsError::BufferLimit)
    ));
    assert_eq!(client.state(), TlsState::Failed);
}
