//! Signed helper declarations. These pure selectors authenticate nothing and
//! confer no execution or filesystem authority on their own.
use crate::resources::{target, valid_digest, valid_resource_alias};
use crate::{LibraryDependency, PackageBinary, PackageManifest};
use alloc::{collections::BTreeSet, string::String};
/// An explicitly public entry point bound to an existing signed native binary.
#[derive(Clone, Debug, Default)]
pub struct ExecutableExport {
    /// Stable logical name; never an installation path supplied by a caller.
    pub name: String,
    /// Canonical path of the package's existing application-kind binary.
    pub binary: String,
}
/// A publisher/key/provenance/ABI-pinned helper dependency.
#[derive(Clone, Debug, Default)]
pub struct ExecutableDependency {
    /// Local alias available only to binaries selecting this dependency.
    pub alias: String,
    /// Authenticated provider constraints, checked separately by the broker.
    pub provider: LibraryDependency,
    /// Logical executable export in that provider's signed manifest.
    pub export: String,
}
/// Select an explicitly exported native entry point. Reject data files,
/// privileged profiles, Linux images and declarations without signed bytes.
pub fn exported<'a>(manifest: &'a PackageManifest, name: &str) -> Option<&'a PackageBinary> {
    if !valid_resource_alias(name) || manifest.linux.is_some() {
        return None;
    }
    let export = manifest
        .executable_exports
        .iter()
        .find(|e| e.name == name)?;
    let binary = manifest.binary(&export.binary)?;
    if binary.kind.as_deref() != Some("application") || binary.capability_profile.is_some() {
        return None;
    }
    let file = manifest
        .files
        .iter()
        .find(|f| Some(&f.id) == binary.file.as_ref())?;
    if target(manifest, &file.path)?.as_str() != binary.path
        || !valid_digest(&file.digest)
        || file.mode & !0o755 != 0
        || file.mode & 0o555 != 0o555
    {
        return None;
    }
    Some(binary)
}
/// Select an own-package export only if the currently authenticated binary
/// explicitly lists it. A sibling's declaration grants no authority.
pub fn own<'a>(manifest: &'a PackageManifest, path: &str, name: &str) -> Option<&'a PackageBinary> {
    if !manifest
        .binary(path)?
        .executable_exports
        .iter()
        .any(|n| n == name)
    {
        return None;
    }
    exported(manifest, name)
}
/// Select one external trust edge only when this binary opted into its alias.
pub fn dependency<'a>(
    manifest: &'a PackageManifest,
    path: &str,
    alias: &str,
) -> Option<&'a ExecutableDependency> {
    if !valid_resource_alias(alias)
        || !manifest
            .binary(path)?
            .executable_dependencies
            .iter()
            .any(|n| n == alias)
    {
        return None;
    }
    manifest
        .executable_dependencies
        .iter()
        .find(|d| d.alias == alias)
}
pub(crate) fn validate(manifest: &PackageManifest) -> Option<()> {
    let mut exports = BTreeSet::new();
    for export in &manifest.executable_exports {
        if !exports.insert(&export.name) || exported(manifest, &export.name).is_none() {
            return None;
        }
    }
    let mut aliases = BTreeSet::new();
    for dep in &manifest.executable_dependencies {
        if !valid_resource_alias(&dep.alias)
            || !aliases.insert(&dep.alias)
            || !valid_resource_alias(&dep.export)
            || !dep.provider.valid()
        {
            return None;
        }
    }
    for binary in &manifest.binaries {
        for (selected, declared) in [
            (&binary.executable_exports, &exports),
            (&binary.executable_dependencies, &aliases),
        ] {
            let mut seen = BTreeSet::new();
            for name in selected {
                if !seen.insert(name) || !declared.contains(name) {
                    return None;
                }
            }
        }
    }
    Some(())
}
