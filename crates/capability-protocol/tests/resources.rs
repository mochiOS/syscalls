use mochios_capability_protocol::resources::*;
#[test]
fn exact_envelopes_and_operation_specific_selectors() {
    for request in [
        Request {
            operation: CHECK,
            alias: "",
            name: "",
        },
        Request {
            operation: OPEN,
            alias: "fonts",
            name: "sans/regular.ttf",
        },
        Request {
            operation: DIRECTORY,
            alias: "engine-data",
            name: "",
        },
    ] {
        let mut out = [0; MAX_BYTES];
        let n = request.encode(&mut out).unwrap();
        let decoded = decode(&out[..n]).unwrap();
        assert_eq!(
            (decoded.operation, decoded.alias, decoded.name),
            (request.operation, request.alias, request.name)
        );
        for end in 0..n {
            assert!(decode(&out[..end]).is_err());
        }
        assert!(decode(&out[..n + 1]).is_err());
        out[6] = 1;
        assert!(decode(&out[..n]).is_err());
    }
}
#[test]
fn text_never_selects_a_package_absolute_path_or_escape() {
    for (operation, alias, name) in [
        (OPEN, "fonts", "../a"),
        (OPEN, "fonts", "/system/a"),
        (DIRECTORY, "fonts", "a"),
        (CHECK, "../fonts", ""),
        (42, "", ""),
        (OPEN, "", "a//b"),
        (OPEN, "", "a\\b"),
        (OPEN, "", "a\0b"),
    ] {
        assert!(
            !Request {
                operation,
                alias,
                name
            }
            .valid()
        );
    }
}
