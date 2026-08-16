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
fn verify_file_golden_and_round_trip() {
    let message = VerifyFile {
        request_id: 0x0807_0605_0403_0201,
        package_len: 0x1817_1615_1413_1211,
        package_digest: [0xaa; 32],
        path: "/system/samples/Chromium-x86_64.mpkg",
    };
    let mut bytes = [0; 256];
    let length = message.encode(&mut bytes).unwrap();
    assert_eq!(length, VERIFY_FILE_FIXED_LEN + message.path.len());
    assert_eq!(&bytes[..8], &[b'M', b'S', b'I', b'G', 1, 0, 4, 0]);
    assert_eq!(&bytes[8..16], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&bytes[24..32], &[17, 18, 19, 20, 21, 22, 23, 24]);
    assert_eq!(&bytes[32..64], &[0xaa; 32]);
    assert_eq!(
        &bytes[64..72],
        &[message.path.len() as u8, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(VerifyFile::decode(&bytes[..length]), Ok(message));
}

#[test]
fn verify_file_rejects_invalid_path_length_reserved_and_output() {
    let message = VerifyFile {
        request_id: 1,
        package_len: 2,
        package_digest: [3; 32],
        path: "/package.mpkg",
    };
    let mut bytes = [0; 128];
    let length = message.encode(&mut bytes).unwrap();

    bytes[66] = 1;
    assert_eq!(
        VerifyFile::decode(&bytes[..length]),
        Err(DecodeError::NonZeroReserved)
    );
    bytes[66] = 0;
    bytes[64..66].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(
        VerifyFile::decode(&bytes[..length]),
        Err(DecodeError::InvalidLength)
    );
    assert!(matches!(
        message.encode(&mut bytes[..length - 1]),
        Err(EncodeError::BufferTooSmall { .. })
    ));

    let invalid = VerifyFile {
        path: "relative",
        ..message
    };
    assert_eq!(invalid.encode(&mut bytes), Err(EncodeError::InvalidPath));
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
fn update_notifications_have_fixed_golden_encoding() {
    let trust = UpdateNotification::trust(
        0x0807_0605_0403_0201,
        0x1817_1615_1413_1211,
        0x2827_2625_2423_2221,
    );
    let mut bytes = [0xff; UPDATE_NOTIFICATION_LEN];
    assert_eq!(trust.encode(&mut bytes), Ok(UPDATE_NOTIFICATION_LEN));
    assert_eq!(
        bytes,
        [
            b'M', b'S', b'I', b'G', 1, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 16, 0, 0, 0, 0, 0, 0, 0,
            17, 18, 19, 20, 21, 22, 23, 24, 33, 34, 35, 36, 37, 38, 39, 40,
        ]
    );
    assert_eq!(UpdateNotification::decode(&bytes), Ok(trust));

    let revocations = UpdateNotification::revocations(u64::MAX, u64::MAX, u64::MAX);
    assert_eq!(revocations.encode(&mut bytes), Ok(UPDATE_NOTIFICATION_LEN));
    assert_eq!(UpdateNotification::decode(&bytes), Ok(revocations));
}

#[test]
fn update_notifications_reject_wrong_opcode_length_and_output() {
    let invalid = UpdateNotification {
        opcode: Opcode::VerifyBegin,
        request_id: 1,
        snapshot_version: 2,
        generation: 3,
    };
    let mut bytes = [0; UPDATE_NOTIFICATION_LEN];
    assert_eq!(invalid.encode(&mut bytes), Err(EncodeError::InvalidOpcode));

    VerifyFinish { request_id: 1 }.encode(&mut bytes).unwrap();
    assert_eq!(
        UpdateNotification::decode(&bytes[..FINISH_LEN]),
        Err(DecodeError::UnexpectedUpdateOpcode(Opcode::VerifyFinish))
    );

    let notification = UpdateNotification::trust(1, 2, 3);
    notification.encode(&mut bytes).unwrap();
    assert_eq!(
        UpdateNotification::decode(&bytes[..UPDATE_NOTIFICATION_LEN - 1]),
        Err(DecodeError::InvalidLength)
    );
    let mut excess = [0; UPDATE_NOTIFICATION_LEN + 1];
    excess[..UPDATE_NOTIFICATION_LEN].copy_from_slice(&bytes);
    assert_eq!(
        UpdateNotification::decode(&excess),
        Err(DecodeError::InvalidLength)
    );
    let mut short = [0; UPDATE_NOTIFICATION_LEN - 1];
    assert!(matches!(
        notification.encode(&mut short),
        Err(EncodeError::BufferTooSmall { .. })
    ));
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
