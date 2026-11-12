use mochios_package_manifest::{executables::*, parse_manifest};
fn source() -> String {
    format!(
        r#"format=1
[package]
id="org.example.code"
name="Code"
version="1"
kind="library"
architecture="x86_64"
abi="example-1"
[[file]]
id="main"
path="/libraries/engine/main"
digest="sha256:{hash}"
size=10
mode="0755"
[[file]]
id="helper"
path="/libraries/engine/helper"
digest="sha256:{hash}"
size=10
mode="0555"
[[binary]]
path="/libraries/engine/main"
file="main"
kind="application"
executable_exports=["worker"]
executable_dependencies=["remote"]
[[binary]]
path="/libraries/engine/helper"
file="helper"
kind="application"
[[executable_export]]
name="worker"
binary="/libraries/engine/helper"
[[executable_dependency]]
alias="remote"
package="org.example.remote"
developer="org.example.publisher"
subject_key_id="{hash}"
provenance="verified-package"
abi="example-1"
export="external-worker"
"#,
        hash = "a".repeat(64)
    )
}
#[test]
fn explicit_exports_are_separate_from_data_and_scoped_per_binary() {
    let m = parse_manifest(&source()).unwrap();
    let root = "/libraries/engine/main";
    assert_eq!(
        own(&m, root, "worker").unwrap().path,
        "/libraries/engine/helper"
    );
    assert_eq!(
        dependency(&m, root, "remote").unwrap().provider.package,
        "org.example.remote"
    );
    assert!(own(&m, "/libraries/engine/helper", "worker").is_none());
    assert!(dependency(&m, "/libraries/engine/helper", "remote").is_none());
    assert!(own(&m, root, "/libraries/engine/helper").is_none());
    assert!(m.resource_exports.is_empty());
    assert!(m.library_dependencies.is_empty());
}
#[test]
fn reject_unbound_data_privileged_profiles_and_unsafe_modes() {
    let s = source();
    for change in [
        s.replace("file=\"helper\"", "file=\"missing\""),
        s.replace("kind=\"application\"", "kind=\"library\""),
        s.replace("mode=\"0555\"", "mode=\"0644\""),
        s.replace("mode=\"0555\"", "mode=\"0777\""),
        s.replace("mode=\"0555\"", "mode=\"4755\""),
        s.replace(
            "file=\"helper\"",
            "file=\"helper\"\ncapability_profile=\"system-service\"",
        ),
        s.replace(
            "executable_exports=[\"worker\"]",
            "executable_exports=[\"unknown\"]",
        ),
        s.replace(
            "executable_dependencies=[\"remote\"]",
            "executable_dependencies=[\"remote\",\"remote\"]",
        ),
        s.replace("name=\"worker\"", "name=\"../worker\""),
        s.replace("alias=\"remote\"", "alias=\"/remote\""),
        s.replace("provenance=\"verified-package\"", "provenance=\"unknown\""),
        s.replace(
            "export=\"external-worker\"",
            "export=\"external-worker\"\nunknown=1",
        ),
    ] {
        assert!(parse_manifest(&change).is_none(), "{change}");
    }
}
#[test]
fn reject_duplicate_exports_and_file_rebinding() {
    let s = source();
    assert!(
        parse_manifest(
            &(s.clone()
                + "\n[[executable_export]]\nname=\"worker\"\nbinary=\"/libraries/engine/main\"\n")
        )
        .is_none()
    );
    assert!(
        parse_manifest(&s.replace(
            "path=\"/libraries/engine/helper\"\ndigest",
            "path=\"/libraries/engine/other\"\ndigest"
        ))
        .is_none()
    );
}
