#[path = "../src/open_variadic.rs"]
mod open_variadic;

#[test]
fn absent_optional_argument_is_never_read() {
    for flags in [0, 1, 2, 0x400, 0x40000, 0x200000, 0x800000] {
        assert_eq!(open_variadic::mode(flags, || panic!("missing vararg read")), 0);
    }
}

#[test]
fn creation_mode_is_read_once_without_truncating_bits() {
    for mode in [0, 0o644, 0o7777, u32::MAX] {
        let mut count = 0;
        assert_eq!(open_variadic::mode(0x0200 | 2, || { count += 1; mode }), mode);
        assert_eq!(count, 1);
    }
}
