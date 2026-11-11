#[path = "../src/resource_view_path.rs"]
mod path;
#[test]
fn serial_is_exact_and_cannot_alias_a_recycled_descriptor_or_partial_token() {
    let mut output = [0; 128];
    let n = path::spell(u64::MAX, &mut output).unwrap();
    assert_eq!(path::parse(&output[..n]), Ok(Some((u64::MAX, n))));
    let root = String::from_utf8(output[..n].to_vec()).unwrap();
    assert!(path::parse(format!("{root}f").as_bytes()).is_err());
    assert!(path::parse(b"/.__mochi_resources/0000000000000000").is_err());
    assert!(path::parse(b"/.__mochi_resources/000000000000000G").is_err());
    assert_eq!(path::parse(b"/system/fonts"), Ok(None));
    assert!(path::spell(0, &mut output).is_err());
}
#[test]
fn canonicalization_preserves_view_authority_and_refuses_parent_escape() {
    let root = "/.__mochi_resources/0000000000000001";
    let mut output = [0; 128];
    for (tail, expected) in [
        ("", ""),
        ("/a/../b", "/b"),
        ("/a/./b/..", "/a"),
        ("//a///", "/a"),
    ] {
        let input = format!("{root}{tail}");
        let n = path::canonical(input.as_bytes(), &mut output).unwrap();
        assert_eq!(&output[..n], format!("{root}{expected}").as_bytes());
    }
    for tail in ["/..", "/a/../../x", "/../0000000000000002/a"] {
        assert!(path::canonical(format!("{root}{tail}").as_bytes(), &mut output).is_err());
    }
}
