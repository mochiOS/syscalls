use mochios_capability_protocol::{
    ProtocolError, RESOLVE_EXECUTION_SECURITY_OPCODE,
    decode_resolve_execution_security_request, encode_resolve_execution_security_request,
};

#[test]
fn execution_security_request_binds_class_and_path() {
    let request = encode_resolve_execution_security_request(3, "/system/apps/example").unwrap();

    assert_eq!(
        u32::from_le_bytes(request[..4].try_into().unwrap()),
        RESOLVE_EXECUTION_SECURITY_OPCODE
    );
    assert_eq!(u64::from_le_bytes(request[4..12].try_into().unwrap()), 3);
    assert_eq!(&request[12..], b"/system/apps/example");
    assert_eq!(
        decode_resolve_execution_security_request(&request),
        Ok((3, "/system/apps/example"))
    );
}

#[test]
fn execution_security_request_rejects_legacy_and_short_frames() {
    let mut legacy = RESOLVE_EXECUTION_SECURITY_OPCODE.to_le_bytes().to_vec();
    legacy.extend_from_slice(b"/system/apps/example");

    assert!(matches!(
        decode_resolve_execution_security_request(&legacy),
        Err(ProtocolError::InvalidField) | Err(ProtocolError::InvalidUtf8)
    ));
    assert_eq!(
        decode_resolve_execution_security_request(
            &RESOLVE_EXECUTION_SECURITY_OPCODE.to_le_bytes()
        ),
        Err(ProtocolError::TooShort)
    );
}
