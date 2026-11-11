use mochios_package_manifest::{parse_manifest, resources::*};
fn manifest() -> String {
    format!(
        r#"format=1
[package]
id="org.example.resources"
name="Example"
version="1"
kind="application"
[application]
entry="entry.elf"
icon="icon.png"
resources=["data/readme.txt"]
[[binary]]
path="/applications/Example.app/entry.elf"
file="code"
kind="application"
resource_exports=["shared"]
resource_dependencies=["fonts"]
[[file]]
id="code"
path="$/entry.elf"
digest="sha256:{hash}"
size=4
mode="0755"
[[file]]
id="icon"
path="$/icon.png"
digest="sha256:{hash}"
size=4
mode="0644"
[[file]]
id="text"
path="$/data/readme.txt"
digest="sha256:{hash}"
size=4
mode="0444"
[[resource_export]]
name="shared"
files={{"readme.txt"="text"}}
[[resource_dependency]]
alias="fonts"
package="org.example.fonts"
developer="org.example.vendor"
subject_key_id="{hash}"
provenance="verified-package"
abi="mochios-1"
export="font-data-v1"
"#,
        hash = "a".repeat(64)
    )
}
#[test]
fn resources_are_separate_and_selected_per_binary() {
    let m = parse_manifest(&manifest()).unwrap();
    assert!(m.library_dependencies.is_empty());
    let binary = "/applications/Example.app/entry.elf";
    let own = own_resources(&m, binary).unwrap();
    assert_eq!(own.len(), 3);
    assert!(
        own.iter().any(|r| r.name == "shared/readme.txt"
            && r.path == "/applications/Example.app/data/readme.txt")
    );
    assert!(own.iter().all(|r| !r.path.ends_with("entry.elf")));
    assert_eq!(
        resource_dependency(&m, binary, "fonts").unwrap().export,
        "font-data-v1"
    );
    assert!(resource_dependency(&m, "/unowned", "fonts").is_err());
    assert!(resource_dependency(&m, binary, "unlisted").is_err());
}
#[test]
fn rejects_escaping_or_ambiguous_logical_names() {
    for value in [
        "", "/root", "../a", "a/../b", "./a", "a//b", "a\\b", "a\0b", "a\nb",
    ] {
        assert!(!valid_resource_name(value), "{value:?}");
    }
    assert!(!valid_resource_name(&"x".repeat(256)));
    for value in ["a", "fonts/regular.ttf", "data-v1/日本語.txt"] {
        assert!(valid_resource_name(value));
    }
}
#[test]
fn rejects_undeclared_files_native_code_and_file_directory_collisions() {
    let source = manifest();
    for changed in [
        source.replace("\"readme.txt\"=\"text\"", "\"readme.txt\"=\"unknown\""),
        source.replace("\"readme.txt\"=\"text\"", "\"readme.txt\"=\"code\""),
        source.replace("\"readme.txt\"=\"text\"", "\"a\"=\"text\",\"a/b\"=\"icon\""),
        source.replace("\"readme.txt\"=\"text\"", "\"../readme.txt\"=\"text\""),
    ] {
        assert!(parse_manifest(&changed).is_none());
    }
}
#[test]
fn rejects_unknown_fields_and_unselected_aliases() {
    assert!(
        parse_manifest(&manifest().replace(
            "export=\"font-data-v1\"",
            "export=\"font-data-v1\"\nextra=true"
        ))
        .is_none()
    );
    assert!(
        parse_manifest(&manifest().replace(
            "resource_dependencies=[\"fonts\"]",
            "resource_dependencies=[\"missing\"]"
        ))
        .is_none()
    );
    assert!(
        parse_manifest(&manifest().replace(
            "resource_exports=[\"shared\"]",
            "resource_exports=[\"shared\",\"shared\"]"
        ))
        .is_none()
    );
}

#[test]
fn canonical_file_alias_cannot_export_the_executable_as_data() {
    let source = manifest().replace(
        "path=\"$/data/readme.txt\"",
        "path=\"/applications/Example.app/entry.elf\"",
    );
    assert!(parse_manifest(&source).is_none());
}

#[test]
fn builtin_bundle_uses_the_signed_entry_location_not_its_display_name() {
    let text = manifest()
        .replace("name=\"Example\"", "name=\"System Monitor\"")
        .replace(
            "/applications/Example.app",
            "/system/applications/SystemMonitor.app",
        )
        .replace("$/", "/system/applications/SystemMonitor.app/");
    let manifest = parse_manifest(&text).unwrap();
    let resources = own_resources(
        &manifest,
        "/system/applications/SystemMonitor.app/entry.elf",
    )
    .unwrap();
    assert_eq!(resources.len(), 3);
    assert!(resources.iter().any(
        |r| r.name == "icon.png" && r.path == "/system/applications/SystemMonitor.app/icon.png"
    ));
}

#[test]
fn legacy_code_only_records_do_not_grant_unmeasured_application_assets() {
    let text = manifest()
        .replace("resource_exports=[\"shared\"]", "resource_exports=[]")
        .replace(
            "[[resource_export]]\nname=\"shared\"\nfiles={\"readme.txt\"=\"text\"}\n",
            "",
        )
        .replace("path=\"$/icon.png\"", "path=\"$/unlisted-icon.png\"")
        .replace("path=\"$/data/readme.txt\"", "path=\"$/unlisted-data.txt\"");
    let manifest = parse_manifest(&text).unwrap();
    assert!(
        own_resources(&manifest, "/applications/Example.app/entry.elf")
            .unwrap()
            .is_empty()
    );
}
