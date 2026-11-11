//! Logical, read-only package assets. Parsing records never authenticates a
//! package or grants authority; services first verify the owning snapshot.
use crate::{LibraryDependency, PackageManifest};
use alloc::{collections::BTreeSet, string::String, vec::Vec};
/// One logical asset bound to an existing signed file record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceFile {
    /// Relative logical name independent of installation paths.
    pub name: String,
    /// Existing regular data file identifier owned by this package.
    pub file: String,
}
/// Publisher-declared, named immutable data export.
#[derive(Clone, Debug, Default)]
pub struct ResourceExport {
    /// Stable contract name; incompatible changes require a new name.
    pub name: String,
    /// Explicit data bindings, never a host directory or symlink.
    pub files: Vec<ResourceFile>,
}
/// Explicit data trust edge; native code dependencies do not imply this grant.
#[derive(Clone, Debug, Default)]
pub struct ResourceDependency {
    /// Alias used by application code, not an arbitrary package selector.
    pub alias: String,
    /// Publisher/key/provenance/ABI constraint checked by the verifier.
    pub provider: LibraryDependency,
    /// Exactly one named export from this authenticated provider.
    pub export: String,
}
/// Check a logical relative path, rejecting escaping or ambiguous components.
pub fn valid_resource_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 4095
        && !name.starts_with('/')
        && !name
            .bytes()
            .any(|b| b == b'\\' || b == 0 || b.is_ascii_control())
        && name
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != ".." && p.len() <= 255)
}
/// Check a bounded, single-component dependency/export alias.
pub fn valid_resource_alias(name: &str) -> bool {
    valid_resource_name(name) && !name.contains('/') && name.len() <= 128
}
/// Check the signed SHA-256 spelling used by asset records.
pub fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
}
pub(crate) fn validate(manifest: &PackageManifest) -> Option<()> {
    let mut exports = BTreeSet::new();
    let mut count = 0usize;
    for export in &manifest.resource_exports {
        count = count.checked_add(export.files.len())?;
        if count > 8192 {
            return None;
        }
        if !valid_resource_alias(&export.name)
            || !exports.insert(&export.name)
            || export.files.is_empty()
            || export.files.len() > 8192
        {
            return None;
        }
        let mut names = BTreeSet::new();
        for asset in &export.files {
            if !valid_resource_name(&asset.name) || !names.insert(asset.name.as_str()) {
                return None;
            }
            let file = manifest.files.iter().find(|f| f.id == asset.file)?;
            let path = target(manifest, &file.path)?;
            if file.mode & !0o666 != 0
                || !valid_digest(&file.digest)
                || manifest
                    .binaries
                    .iter()
                    .any(|b| b.file.as_ref() == Some(&asset.file) || b.path == path)
            {
                return None;
            }
        }
        for name in &names {
            for (i, _) in name.match_indices('/') {
                if names.contains(&name[..i]) {
                    return None;
                }
            }
        }
    }
    let mut aliases = BTreeSet::new();
    for dep in &manifest.resource_dependencies {
        if !valid_resource_alias(&dep.alias)
            || !aliases.insert(&dep.alias)
            || !valid_resource_alias(&dep.export)
            || !dep.provider.valid()
        {
            return None;
        }
    }
    for binary in &manifest.binaries {
        let mut selected = BTreeSet::new();
        for name in &binary.resource_exports {
            if !selected.insert(name) || !exports.contains(name) {
                return None;
            }
        }
        let mut selected = BTreeSet::new();
        for name in &binary.resource_dependencies {
            if !selected.insert(name) || !aliases.contains(name) {
                return None;
            }
        }
    }
    Some(())
}

/// An inert file binding selected from an authenticated manifest. The consumer
/// must verify captured bytes against `digest` before publishing a reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedResource {
    /// Relative name visible in the read-only resource view.
    pub name: String,
    /// Canonical installation target, never supplied by the requesting process.
    pub path: String,
    /// Expected signed byte length.
    pub size: u64,
    /// Expected signed SHA-256 spelling.
    pub digest: String,
}
/// A rejected declaration or absent, unauthorized resource selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceError {
    /// The signed declaration is malformed or ambiguous.
    InvalidDeclaration,
    /// A requested alias or exported asset does not exist.
    NotFound,
    /// The measured executable did not select this resource set.
    NotAllowed,
}

fn target(manifest: &PackageManifest, path: &str) -> Option<String> {
    let path = if let Some(relative) = path.strip_prefix("$/") {
        if !valid_resource_name(relative) {
            return None;
        }
        match manifest.package_kind.as_deref() {
            Some("application") => {
                alloc::format!("/applications/{}.app/{relative}", manifest.package_name)
            }
            Some("binary") | None => alloc::format!("/bin/{relative}"),
            _ => return None,
        }
    } else {
        path.into()
    };
    let relative = path.strip_prefix('/')?;
    valid_resource_name(relative).then_some(path)
}
fn binding(
    manifest: &PackageManifest,
    name: &str,
    file: &crate::PackageFile,
) -> Result<SelectedResource, ResourceError> {
    let path = target(manifest, &file.path).ok_or(ResourceError::InvalidDeclaration)?;
    if !valid_resource_name(name)
        || !valid_digest(&file.digest)
        || file.mode & !0o666 != 0
        || manifest
            .binaries
            .iter()
            .any(|b| b.file.as_ref() == Some(&file.id) || b.path == path)
    {
        return Err(ResourceError::InvalidDeclaration);
    }
    Ok(SelectedResource {
        name: name.into(),
        path,
        size: file.size,
        digest: file.digest.clone(),
    })
}
/// Select a publisher's explicit export. This function does not authenticate the
/// provider; the broker must first check its install record and trust edge.
pub fn exported_resources(
    manifest: &PackageManifest,
    name: &str,
) -> Result<Vec<SelectedResource>, ResourceError> {
    validate(manifest).ok_or(ResourceError::InvalidDeclaration)?;
    let export = manifest
        .resource_exports
        .iter()
        .find(|e| e.name == name)
        .ok_or(ResourceError::NotFound)?;
    export
        .files
        .iter()
        .map(|asset| {
            binding(
                manifest,
                &asset.name,
                manifest
                    .files
                    .iter()
                    .find(|f| f.id == asset.file)
                    .ok_or(ResourceError::InvalidDeclaration)?,
            )
        })
        .collect()
}
/// Select an external asset declaration only when the measured executable's
/// signed binary record explicitly enables its alias. No transitive code grant.
pub fn resource_dependency<'a>(
    manifest: &'a PackageManifest,
    binary: &str,
    alias: &str,
) -> Result<&'a ResourceDependency, ResourceError> {
    validate(manifest).ok_or(ResourceError::InvalidDeclaration)?;
    let binary = manifest.binary(binary).ok_or(ResourceError::NotAllowed)?;
    if !binary
        .resource_dependencies
        .iter()
        .any(|name| name == alias)
    {
        return Err(ResourceError::NotAllowed);
    }
    manifest
        .resource_dependencies
        .iter()
        .find(|d| d.alias == alias)
        .ok_or(ResourceError::NotFound)
}
/// Select only declared application assets and explicitly selected own exports.
/// Selected exports appear under `export-name/`; application assets keep their
/// existing bundle-relative names. Installation paths are not public API names.
pub fn own_resources(
    manifest: &PackageManifest,
    binary: &str,
) -> Result<Vec<SelectedResource>, ResourceError> {
    validate(manifest).ok_or(ResourceError::InvalidDeclaration)?;
    let executable = manifest.binary(binary).ok_or(ResourceError::NotAllowed)?;
    let mut selected = Vec::new();
    if let Some(app) = &manifest.application {
        // Built-in bundles may live on System and their display name need
        // not equal the directory name. Anchor data to the authenticated
        // executable's signed entry suffix, never to a guessed install path.
        if let Some(bundle) = binary
            .strip_suffix(&app.entry)
            .filter(|base| base.ends_with(".app/"))
        {
            for name in app
                .resources
                .iter()
                .chain((!app.icon.is_empty()).then_some(&app.icon))
            {
                if selected.iter().any(|r: &SelectedResource| r.name == *name) {
                    continue;
                }
                if !valid_resource_name(name) {
                    return Err(ResourceError::InvalidDeclaration);
                }
                let path = alloc::format!("{bundle}{name}");
                // Older installed manifests authenticated code only. Keep
                // them launchable, but never grant an unmeasured data file.
                let Some(file) = manifest
                    .files
                    .iter()
                    .find(|f| target(manifest, &f.path).as_ref() == Some(&path))
                else {
                    continue;
                };
                selected.push(binding(manifest, name, file)?);
            }
        }
    }
    for name in &executable.resource_exports {
        for mut resource in exported_resources(manifest, name)? {
            resource.name = alloc::format!("{name}/{}", resource.name);
            if !valid_resource_name(&resource.name)
                || selected.iter().any(|r| r.name == resource.name)
            {
                return Err(ResourceError::InvalidDeclaration);
            }
            selected.push(resource);
        }
    }
    if selected.len() > 8192 {
        return Err(ResourceError::InvalidDeclaration);
    }
    let names: BTreeSet<_> = selected.iter().map(|r| r.name.as_str()).collect();
    for name in &names {
        for (i, _) in name.match_indices('/') {
            if names.contains(&name[..i]) {
                return Err(ResourceError::InvalidDeclaration);
            }
        }
    }
    Ok(selected)
}
