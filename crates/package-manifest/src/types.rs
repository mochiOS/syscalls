use crate::validation::is_valid_package_id;
use alloc::{string::String, vec::Vec};

#[derive(Clone, Debug, Default)]
pub struct PackageBinary {
    pub path: String,
    pub file: Option<String>,
    pub capability_profile: Option<String>,
    pub requires: Vec<String>,
    pub kind: Option<String>,
    pub driver_class: Option<String>,
    pub api_version: Option<u32>,
    pub match_bus: Option<String>,
    pub match_class: Option<String>,
    pub match_vendor_id: Option<String>,
    pub match_device_id: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct PackageFile {
    pub id: String,
    pub path: String,
    pub digest: String,
    pub size: u64,
    pub mode: u32,
}

/// An explicit trust edge for the native libraries exported by another package.
/// Version updates may change file digests, but not this publisher, key or ABI.
#[derive(Clone, Debug, Default)]
pub struct LibraryDependency {
    pub package: String,
    pub developer: String,
    pub subject_key_id: String,
    pub provenance: String,
    pub abi: String,
}

impl LibraryDependency {
    pub(crate) fn valid(&self) -> bool {
        is_valid_package_id(&self.package)
            && !self.developer.is_empty()
            && !self.developer.bytes().any(|byte| byte.is_ascii_control())
            && self.subject_key_id.len() == 64
            && self
                .subject_key_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            && matches!(
                self.provenance.as_str(),
                "built-in" | "verified-package" | "development"
            )
            && !self.abi.is_empty()
            && !self.abi.bytes().any(|byte| byte.is_ascii_control())
    }
}

#[derive(Clone, Debug, Default)]
pub struct LinuxApplication {
    pub entrypoint: String,
    pub rootfs_file: String,
    pub writable_paths: Vec<String>,
    pub portal_read_paths: Vec<String>,
    pub portal_write_paths: Vec<String>,
    pub network: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ApplicationMetadata {
    pub entry: String,
    pub description: String,
    pub icon: String,
    pub resources: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct PackageManifest {
    pub package_id: String,
    pub package_name: String,
    pub package_version: String,
    pub install_provenance: Option<String>,
    pub vendor: Option<String>,
    pub package_kind: Option<String>,
    pub package_architecture: Option<String>,
    pub package_abi: Option<String>,
    pub files: Vec<PackageFile>,
    pub library_dependencies: Vec<LibraryDependency>,
    pub binaries: Vec<PackageBinary>,
    pub application: Option<ApplicationMetadata>,
    pub linux: Option<LinuxApplication>,
}

impl PackageManifest {
    pub fn binary(&self, path: &str) -> Option<&PackageBinary> {
        self.binaries.iter().find(|binary| binary.path == path)
    }

    pub fn binary_requires(&self, path: &str) -> Option<&[String]> {
        self.binary(path).map(|binary| binary.requires.as_slice())
    }
}
