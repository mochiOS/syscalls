use ed25519_dalek::{Signer, SigningKey};
use mochios_certificate::{
    DOMAIN_SEPARATOR, DeveloperCertificate, EncodeError, FORMAT_VERSION, HEADER_LEN,
    KEY_USAGE_PACKAGE_SIGNING, MAGIC, PackageIdScope, SIGNATURE_LEN, ValidationError, VerifyError,
    is_valid_developer_id, is_valid_package_id, key_id,
};

const DEVELOPER_ID: &str = "019f9e5ac6687902b0e72fe53abfbef1";

fn signed_certificate() -> (DeveloperCertificate, [u8; 32]) {
    let root = SigningKey::from_bytes(&[7u8; 32]);
    let developer = SigningKey::from_bytes(&[9u8; 32]);
    let root_public = root.verifying_key().to_bytes();
    let subject_public_key = developer.verifying_key().to_bytes();
    let mut certificate = DeveloperCertificate {
        serial_number: 42,
        issuer_key_id: key_id(&root_public),
        developer_id: DEVELOPER_ID.into(),
        subject_key_id: key_id(&subject_public_key),
        subject_public_key,
        not_before: 1_700_000_000,
        not_after: 1_900_000_000,
        key_usage: KEY_USAGE_PACKAGE_SIGNING,
        package_id_scopes: vec![
            PackageIdScope::exact("com.example.single"),
            PackageIdScope::prefix("org.mochios"),
        ],
        allowed_capabilities: vec!["fs.read.all".into(), "window.create".into()],
        signature: [0; SIGNATURE_LEN],
    };
    certificate.signature = root
        .sign(&certificate.signing_message().unwrap())
        .to_bytes();
    (certificate, root_public)
}

fn encode(certificate: &DeveloperCertificate) -> Vec<u8> {
    let mut bytes = vec![0; certificate.encoded_len().unwrap()];
    let length = certificate.encode(&mut bytes).unwrap();
    assert_eq!(length, bytes.len());
    bytes
}

#[test]
fn round_trip_and_verify() {
    let (certificate, root_public) = signed_certificate();
    let decoded = DeveloperCertificate::decode(&encode(&certificate)).unwrap();
    assert_eq!(decoded, certificate);
    let verified = decoded
        .verify(&root_public, 1_800_000_000, "org.mochios.app.demo")
        .unwrap();
    assert!(verified.allows_capability("window.create"));
    assert!(!verified.allows_capability("window.overlay"));
}

#[test]
fn fixed_header_and_domain_are_stable() {
    let (certificate, _) = signed_certificate();
    let bytes = encode(&certificate);
    assert_eq!(&bytes[0..4], &MAGIC);
    assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), FORMAT_VERSION);
    assert_eq!(
        u16::from_le_bytes([bytes[6], bytes[7]]) as usize,
        HEADER_LEN
    );
    assert_eq!(
        u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize,
        bytes.len()
    );
    let message = certificate.signing_message().unwrap();
    assert_eq!(&message[..DOMAIN_SEPARATOR.len()], DOMAIN_SEPARATOR);
    assert_eq!(
        message.len(),
        DOMAIN_SEPARATOR.len() + bytes.len() - SIGNATURE_LEN
    );
}

#[test]
fn rejects_unknown_header_values_and_trailing_bytes() {
    let (certificate, _) = signed_certificate();
    let bytes = encode(&certificate);
    for (offset, value) in [(0, 0xff), (4, 2), (6, 1), (142, 1)] {
        let mut malformed = bytes.clone();
        malformed[offset] = value;
        assert!(DeveloperCertificate::decode(&malformed).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(DeveloperCertificate::decode(&trailing).is_err());
}

#[test]
fn rejects_subject_key_id_mismatch() {
    let (certificate, _) = signed_certificate();
    let mut bytes = encode(&certificate);
    bytes[52] ^= 1;
    assert!(matches!(
        DeveloperCertificate::decode(&bytes),
        Err(mochios_certificate::DecodeError::Validation(
            ValidationError::SubjectKeyIdMismatch
        ))
    ));
}

#[test]
fn rejects_unsorted_and_duplicate_items() {
    let (mut certificate, _) = signed_certificate();
    certificate.package_id_scopes.swap(0, 1);
    assert_eq!(
        certificate.validate(),
        Err(ValidationError::UnsortedPackageScopes)
    );
    let (mut certificate, _) = signed_certificate();
    certificate.allowed_capabilities[1] = "fs.read.all".into();
    assert_eq!(
        certificate.validate(),
        Err(ValidationError::DuplicateAllowedCapability)
    );
}

#[test]
fn exact_and_dot_boundary_prefix_scopes_are_enforced() {
    let (certificate, root_public) = signed_certificate();
    assert!(
        certificate
            .verify(&root_public, 1_800_000_000, "com.example.single")
            .is_ok()
    );
    assert!(
        certificate
            .verify(&root_public, 1_800_000_000, "org.mochios")
            .is_ok()
    );
    assert!(
        certificate
            .verify(&root_public, 1_800_000_000, "org.mochios.app")
            .is_ok()
    );
    assert_eq!(
        certificate.verify(&root_public, 1_800_000_000, "org.mochiosx"),
        Err(VerifyError::PackageIdNotAllowed)
    );
}

#[test]
fn validity_is_half_open() {
    let (certificate, root_public) = signed_certificate();
    assert_eq!(
        certificate.verify(&root_public, certificate.not_before - 1, "org.mochios"),
        Err(VerifyError::NotYetValid)
    );
    assert!(
        certificate
            .verify(&root_public, certificate.not_before, "org.mochios")
            .is_ok()
    );
    assert_eq!(
        certificate.verify(&root_public, certificate.not_after, "org.mochios"),
        Err(VerifyError::Expired)
    );
}

#[test]
fn root_and_signature_must_match() {
    let (mut certificate, root_public) = signed_certificate();
    let other_root = SigningKey::from_bytes(&[11u8; 32])
        .verifying_key()
        .to_bytes();
    assert_eq!(
        certificate.verify(&other_root, 1_800_000_000, "org.mochios"),
        Err(VerifyError::IssuerKeyIdMismatch)
    );
    certificate.signature[0] ^= 1;
    assert_eq!(
        certificate.verify(&root_public, 1_800_000_000, "org.mochios"),
        Err(VerifyError::InvalidSignature)
    );
}

#[test]
fn root_signature_is_checked_before_validity_and_scope() {
    let (mut certificate, root_public) = signed_certificate();
    certificate.signature[0] ^= 1;
    assert_eq!(
        certificate.verify(&root_public, certificate.not_after, "org.invalid"),
        Err(VerifyError::InvalidSignature)
    );
}

#[test]
fn encode_reports_small_buffer() {
    let (certificate, _) = signed_certificate();
    let required = certificate.encoded_len().unwrap();
    let mut bytes = vec![0; required - 1];
    assert_eq!(
        certificate.encode(&mut bytes),
        Err(EncodeError::BufferTooSmall {
            required,
            actual: required - 1,
        })
    );
}

#[test]
fn rejects_noncanonical_strings_and_unknown_usage() {
    let (mut certificate, _) = signed_certificate();
    certificate.developer_id = "開発者".into();
    assert_eq!(
        certificate.validate(),
        Err(ValidationError::InvalidDeveloperId)
    );
    let (mut certificate, _) = signed_certificate();
    certificate.package_id_scopes[0].package_id = "com.example.*".into();
    assert_eq!(
        certificate.validate(),
        Err(ValidationError::InvalidPackageScope)
    );
    let (mut certificate, _) = signed_certificate();
    certificate.key_usage |= 2;
    assert_eq!(
        certificate.validate(),
        Err(ValidationError::UnknownKeyUsage { actual: 3 })
    );
}

#[test]
fn developer_ids_are_uuid_v7_lowercase_hex() {
    assert!(is_valid_developer_id(DEVELOPER_ID));
    for invalid in [
        "",
        "019f9e5a-c668-7902-b0e7-2fe53abfbef1",
        "org.mochios.developer.019f9e5ac6687902b0e72fe53abfbef1",
        "019F9E5AC6687902B0E72FE53ABFBEF1",
        "019f9e5ac6686902b0e72fe53abfbef1",
        "019f9e5ac6687902c0e72fe53abfbef1",
        "019f9e5ac6687902b0e72fe53abfbefg",
    ] {
        assert!(!is_valid_developer_id(invalid), "accepted {invalid}");
    }
}

#[test]
fn package_ids_follow_the_shared_reverse_domain_contract() {
    for valid in [
        "com.example.app",
        "io.github.user.app",
        "dev.tas0.tool",
        "org.mochios.app",
        "1.example-app",
    ] {
        assert!(is_valid_package_id(valid), "rejected {valid}");
    }
    for invalid in [
        "app",
        "Com.example.app",
        ".com.example",
        "com.example.",
        "com..example",
        "com.example_app",
        "-com.example",
        "com-.example",
        "com.-example",
        "com.example-",
    ] {
        assert!(!is_valid_package_id(invalid), "accepted {invalid}");
    }
}
