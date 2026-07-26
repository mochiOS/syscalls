use mochios_signature_protocol::*;

#[test]
fn begin_golden_and_round_trip() {
    let message = VerifyBegin {
        request_id: 0x0807_0605_0403_0201,
        package_len: 7,
        package_digest: [0xaa; 32],
    };
    let mut bytes = [0; BEGIN_LEN];
    assert_eq!(message.encode(&mut bytes), Ok(BEGIN_LEN));
    assert_eq!(&bytes[..8], &[b'M', b'S', b'I', b'G', 1, 0, 1, 0]);
    assert_eq!(&bytes[8..16], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(VerifyBegin::decode(&bytes), Ok(message));
}

#[test]
fn chunk_and_finish_round_trip() {
    let chunk = VerifyChunk {
        request_id: 9,
        offset: 4,
        bytes: b"package",
    };
    let mut bytes = [0; 64];
    let len = chunk.encode(&mut bytes).unwrap();
    assert_eq!(VerifyChunk::decode(&bytes[..len]), Ok(chunk));
    let finish = VerifyFinish { request_id: 9 };
    assert_eq!(finish.encode(&mut bytes), Ok(FINISH_LEN));
    assert_eq!(VerifyFinish::decode(&bytes[..FINISH_LEN]), Ok(finish));
    let status = StatusResponse {
        request_id: 9,
        status: 0,
    };
    assert_eq!(status.encode(&mut bytes), Ok(ERROR_LEN));
    assert_eq!(StatusResponse::decode(&bytes[..ERROR_LEN]), Ok(status));
}

#[test]
fn verified_round_trip() {
    let capabilities = ["fs.read.all", "process.spawn"];
    let message = VerifiedResponse {
        request_id: u64::MAX,
        certificate_serial: 42,
        subject_key_id: [1; 32],
        manifest_digest: [2; 32],
        package_digest: [3; 32],
        developer_id: "org.mochios.development",
        verified_package_id: "org.mochios.demo",
        allowed_capabilities: &capabilities,
    };
    let mut bytes = [0; 512];
    let len = message.encode(&mut bytes).unwrap();
    let decoded = VerifiedView::decode(&bytes[..len]).unwrap();
    assert_eq!(decoded.request_id, u64::MAX);
    assert_eq!(decoded.certificate_serial, 42);
    assert_eq!(decoded.developer_id, message.developer_id);
    assert_eq!(decoded.verified_package_id, message.verified_package_id);
    assert_eq!(
        decoded
            .allowed_capabilities()
            .collect::<Result<std::vec::Vec<_>, _>>()
            .unwrap(),
        capabilities
    );
}

#[test]
fn malformed_headers_and_lengths_are_rejected() {
    let mut bytes = [0; FINISH_LEN];
    VerifyFinish { request_id: 1 }.encode(&mut bytes).unwrap();
    bytes[0] = 0;
    assert!(matches!(
        VerifyFinish::decode(&bytes),
        Err(DecodeError::InvalidMagic(_))
    ));
    bytes[0] = b'M';
    bytes[4] = 2;
    assert!(matches!(
        VerifyFinish::decode(&bytes),
        Err(DecodeError::UnsupportedVersion(2))
    ));
    bytes[4] = 1;
    bytes[6..8].copy_from_slice(&99u16.to_le_bytes());
    assert!(matches!(
        decode_opcode(&bytes),
        Err(DecodeError::UnknownOpcode(99))
    ));
    assert_eq!(
        VerifyFinish::decode(&bytes[..10]),
        Err(DecodeError::InvalidLength)
    );
}

#[test]
fn excess_bytes_reserved_and_small_output_are_rejected() {
    let message = VerifyBegin {
        request_id: 1,
        package_len: 1,
        package_digest: [0; 32],
    };
    let mut bytes = [0; BEGIN_LEN + 1];
    assert_eq!(message.encode(&mut bytes), Ok(BEGIN_LEN));
    assert_eq!(VerifyBegin::decode(&bytes), Err(DecodeError::InvalidLength));
    let mut short = [0; BEGIN_LEN - 1];
    assert!(matches!(
        message.encode(&mut short),
        Err(EncodeError::BufferTooSmall { .. })
    ));
    let error = ErrorResponse {
        request_id: 2,
        status: -22,
    };
    let mut error_bytes = [0; ERROR_LEN];
    error.encode(&mut error_bytes).unwrap();
    error_bytes[28] = 1;
    assert_eq!(
        ErrorResponse::decode(&error_bytes),
        Err(DecodeError::NonZeroReserved)
    );
}
