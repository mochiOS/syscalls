use super::*;
use crate::stream::Stream;

fn pair() -> (Stream, ServerConnection) {
    let identity = test_identity("localhost");
    let roots = root_store_from_der(&[identity.root.der().as_ref()]).unwrap();
    let mut config =
        build_client_config(roots, Arc::new(FixedTimeProvider::at(VALID_TIME))).unwrap();
    crate::set_client_alpn(&mut config, &[b"h2".to_vec(), b"http/1.1".to_vec()]).unwrap();
    let mut client = Stream::new(Arc::new(config), "localhost").unwrap();
    let provider = Arc::new(crypto_provider());
    let mut server_config =
        ServerConfig::builder_with_details(provider, Arc::new(FixedTimeProvider::at(VALID_TIME)))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![identity.leaf.der().clone()],
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(identity.leaf_key.serialize_der())),
            )
            .unwrap();
    server_config.send_tls13_tickets = 0;
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    for _ in 0..128 {
        while !client.ciphertext().is_empty() {
            let count = client.ciphertext().len().min(7);
            receive_at_server(&mut server, &client.ciphertext()[..count]).unwrap();
            client.consume_ciphertext(count).unwrap();
        }
        for chunk in transmit_from_server(&mut server).chunks(5) {
            client.receive_tls(chunk).unwrap();
        }
        if client.state() == TlsState::Established && !server.is_handshaking() {
            return (client, server);
        }
    }
    panic!("bounded fragmented handshake failed");
}
#[test]
fn partial_records_alpn_plaintext_and_close_metadata() {
    let (mut client, mut server) = pair();
    assert_eq!(
        client.connection().negotiated_protocol(),
        Some(b"h2".as_slice())
    );
    client.write(b"request").unwrap();
    receive_at_server(&mut server, client.ciphertext()).unwrap();
    let size = client.ciphertext().len();
    client.consume_ciphertext(size).unwrap();
    let mut bytes = [0; 7];
    server.reader().read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"request");
    server.writer().write_all(b"response").unwrap();
    for byte in transmit_from_server(&mut server) {
        client.receive_tls(&[byte]).unwrap();
    }
    assert_eq!(client.plaintext(), b"response");
    client.consume_plaintext(3).unwrap();
    assert_eq!(client.plaintext(), b"ponse");
    assert_eq!(client.consume_plaintext(6), Err(TlsError::InvalidState));
    server.send_close_notify();
    client
        .receive_tls(&transmit_from_server(&mut server))
        .unwrap();
    assert_eq!(client.state(), TlsState::PeerClosed);
    assert!(client.connection().peer_certificate_info().is_ok());
    assert_eq!(
        client.connection().negotiated_protocol(),
        Some(b"h2".as_slice())
    );
}
#[test]
fn backpressure_preserves_ciphertext_and_nonce() {
    let (mut client, mut server) = pair();
    let record = vec![0x61; crate::MAX_TLS_PLAINTEXT];
    for _ in 0..3 {
        client.write(&record).unwrap();
    }
    let before = client.ciphertext().to_vec();
    assert_eq!(client.write(b"retry"), Err(TlsError::BufferLimit));
    assert_eq!(client.ciphertext(), before);
    let mut received = Vec::new();
    let mut deliver = |server: &mut ServerConnection, bytes: &[u8]| {
        for chunk in bytes.chunks(1024) {
            receive_at_server(server, chunk).unwrap();
            let mut buffer = [0; 8192];
            loop {
                match server.reader().read(&mut buffer) {
                    Ok(0) => break,
                    Ok(size) => received.extend_from_slice(&buffer[..size]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => panic!("test peer read failed: {e}"),
                }
            }
        }
    };
    deliver(&mut server, client.ciphertext());
    client.consume_ciphertext(before.len()).unwrap();
    client.write(b"retry").unwrap();
    deliver(&mut server, client.ciphertext());
    assert_eq!(received.len(), record.len() * 3 + 5);
    assert_eq!(&received[record.len() * 3..], b"retry");
}
#[test]
fn authentication_failure_is_sticky() {
    let (mut client, mut server) = pair();
    server.writer().write_all(b"secret").unwrap();
    let mut bytes = transmit_from_server(&mut server);
    *bytes.last_mut().unwrap() ^= 1;
    assert_eq!(
        client.receive_tls(&bytes),
        Err(TlsError::AuthenticationFailed)
    );
    assert_eq!(client.state(), TlsState::Failed);
    assert!(client.plaintext().is_empty());
    assert_eq!(client.advance(), Err(TlsError::AuthenticationFailed));
    assert_eq!(client.write(b"no"), Err(TlsError::AuthenticationFailed));
}
#[test]
fn alpn_limits_preserve_security_defaults() {
    let mut config = build_client_config(
        crate::production_root_store(),
        Arc::new(FixedTimeProvider::at(VALID_TIME)),
    )
    .unwrap();
    for offer in [
        vec![vec![]],
        vec![vec![b'x'; 256]],
        vec![b"h2".to_vec(), b"h2".to_vec()],
        vec![vec![b'a']; 17],
    ] {
        assert_eq!(
            crate::set_client_alpn(&mut config, &offer),
            Err(TlsError::InvalidConfiguration)
        );
        assert!(config.alpn_protocols.is_empty());
    }
    crate::set_client_alpn(&mut config, &[b"h2".to_vec()]).unwrap();
    assert!(!config.enable_early_data);
    assert!(!config.enable_secret_extraction);
    assert!(config.enable_sni);
}
