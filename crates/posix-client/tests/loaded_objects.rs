use mochios_posix_client::{
    loaded_objects,
    pie::{Pie, link_scope::Object},
};

#[path = "common/loaded_image.rs"]
mod common;
use common::source;

#[test]
fn real_shared_elf_dynamic_symbols_resolve_to_their_captured_names_and_addresses() {
    struct Temporary(std::path::PathBuf);
    impl Drop for Temporary {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let temporary = Temporary(
        std::env::temp_dir().join(format!("mochi-loader-symbols-{}", std::process::id())),
    );
    std::fs::create_dir_all(&temporary.0).unwrap();
    let source = temporary.0.join("library.c");
    let library = temporary.0.join("library.so");
    std::fs::write(
        &source,
        "int exported_data = 17; int exported_function(int x) { return x + 1; }\n",
    )
    .unwrap();
    let compiled = std::process::Command::new("cc")
        .args(["-shared", "-fPIC", "-nostdlib", "-Wl,--hash-style=both"])
        .arg(&source)
        .arg("-o")
        .arg(&library)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let symbols = std::process::Command::new("nm")
        .args(["-D", "--defined-only"])
        .arg(&library)
        .output()
        .unwrap();
    assert!(symbols.status.success());
    let bytes = std::fs::read(library).unwrap();
    let image = Pie::parse_object(&bytes).unwrap();
    let objects = [Object {
        name: b"",
        image: &image,
        bias: 0x20000000,
    }];
    let mut encoded = vec![0; loaded_objects::encoded_length(&objects, b"library.so").unwrap()];
    loaded_objects::encode(&objects, b"library.so", &mut encoded).unwrap();
    let parsed = loaded_objects::Image::parse(&encoded).unwrap();
    let entry = parsed.entry(0).unwrap();
    let mut found = 0;
    for line in String::from_utf8(symbols.stdout).unwrap().lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 3 || !fields[2].starts_with("exported_") {
            continue;
        }
        let address = 0x20000000 + u64::from_str_radix(fields[0], 16).unwrap();
        assert!(entry.contains(address));
        assert_eq!(entry.symbol(address), Some((fields[2].as_bytes(), address)));
        found += 1;
    }
    assert_eq!(found, 2);
}

#[test]
fn actual_captured_headers_use_elf_phoff_and_keep_object_extents() {
    let source = source();
    let image = Pie::parse_object(&source).unwrap();
    let objects = [Object {
        name: b"",
        image: &image,
        bias: 0x20000000,
    }];
    let mut encoded =
        vec![0xa5; loaded_objects::encoded_length(&objects, b"/lib/example.so").unwrap()];
    loaded_objects::encode(&objects, b"/lib/example.so", &mut encoded).unwrap();
    let snapshot = loaded_objects::Image::parse(&encoded).unwrap();
    assert_eq!(snapshot.count(), 1);
    let entry = snapshot.entry(0).unwrap();
    assert_eq!(entry.headers, &source[128..184]);
    assert_eq!(entry.name, b"/lib/example.so");
    assert_eq!(entry.base(), 0x20000000);
    assert!(entry.contains(0x20001000));
    assert!(!entry.contains(0x20002000));
    assert!(!entry.contains(0x1fffffff));
    assert_eq!(entry.symbol(0x20001000), None);
    assert!(snapshot.entry(1).is_err());
}

#[test]
fn truncated_offsets_and_overflowing_load_addresses_are_rejected_without_panics() {
    let source = source();
    let image = Pie::parse_object(&source).unwrap();
    let objects = [Object {
        name: b"",
        image: &image,
        bias: 0x20000000,
    }];
    let mut encoded = vec![0; loaded_objects::encoded_length(&objects, b"x").unwrap()];
    loaded_objects::encode(&objects, b"x", &mut encoded).unwrap();
    for length in 0..encoded.len() {
        assert!(loaded_objects::Image::parse(&encoded[..length]).is_err());
    }
    for field in [
        8,
        16,
        24 + 8,
        24 + 16,
        24 + 24,
        24 + 32,
        24 + 40,
        24 + 48,
        24 + 56,
    ] {
        let mut corrupt = encoded.clone();
        corrupt[field..field + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            loaded_objects::Image::parse(&corrupt).is_err(),
            "field {field}"
        );
    }
    let mut corrupt = encoded.clone();
    corrupt[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(loaded_objects::Image::parse(&corrupt).is_err());
    // Random malformed metadata must never panic, including hostile offsets.
    let mut random = 0x12456789u64;
    for _ in 0..2000 {
        let mut corrupt = encoded.clone();
        random ^= random << 13;
        random ^= random >> 7;
        random ^= random << 17;
        let index = random as usize % corrupt.len();
        corrupt[index] ^= (random >> 32) as u8;
        let _ = loaded_objects::Image::parse(&corrupt);
    }
}

#[test]
fn several_objects_preserve_alignment_and_nul_termination() {
    let source = source();
    let image = Pie::parse_object(&source).unwrap();
    let objects = [
        Object {
            name: b"",
            image: &image,
            bias: 0x20000000,
        },
        Object {
            name: b"second.so",
            image: &image,
            bias: 0x30000000,
        },
    ];
    let mut encoded = vec![0; loaded_objects::encoded_length(&objects, b"first.so").unwrap()];
    loaded_objects::encode(&objects, b"first.so", &mut encoded).unwrap();
    let snapshot = loaded_objects::Image::parse(&encoded).unwrap();
    assert_eq!(snapshot.count(), 2);
    assert_eq!(snapshot.entry(1).unwrap().name, b"second.so");
    for index in 0..2 {
        let entry = snapshot.entry(index).unwrap();
        assert_eq!(entry.headers.as_ptr() as usize % 8, 0);
        assert_eq!(unsafe { *entry.name.as_ptr().add(entry.name.len()) }, 0);
    }
}
