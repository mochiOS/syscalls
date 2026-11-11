use crate::*;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use toml::{Table, Value};

const MAX_ENTRIES: usize = 8192;
const MAX_REQUIREMENTS: usize = 256;

fn optional_string(table: &Table, key: &str) -> Option<Option<String>> {
    match table.get(key) {
        None => Some(None),
        Some(Value::String(value)) => Some(Some(value.clone())),
        _ => None,
    }
}

fn string(table: &Table, key: &str) -> Option<String> {
    Some(optional_string(table, key)?.unwrap_or_default())
}

fn alias(table: &Table, key: &str, other: &str) -> Option<Option<String>> {
    let value = optional_string(table, key)?;
    let alternate = optional_string(table, other)?;
    if value.is_some() && alternate.is_some() {
        return None;
    }
    Some(value.or(alternate))
}

fn strings(table: &Table, key: &str, limit: usize) -> Option<Vec<String>> {
    let Some(value) = table.get(key) else {
        return Some(Vec::new());
    };
    let values = value.as_array()?;
    if values.len() > limit {
        return None;
    }
    values
        .iter()
        .map(|value| value.as_str().map(String::from))
        .collect()
}

fn requirements(table: &Table) -> Option<Vec<String>> {
    capability_list(table, "requires")
}

fn capability_list(table: &Table, key: &str) -> Option<Vec<String>> {
    let requires = strings(table, key, MAX_REQUIREMENTS)?;
    for (index, requirement) in requires.iter().enumerate() {
        if requirement.is_empty()
            || requirement.len() > 128
            || requirement.bytes().any(|b| b.is_ascii_control())
            || requires[index + 1..].contains(requirement)
        {
            return None;
        }
    }
    Some(requires)
}

fn number(value: &Value) -> Option<u64> {
    match value {
        Value::Integer(value) => u64::try_from(*value).ok(),
        Value::String(value) => {
            if let Some(hex) = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
            {
                u64::from_str_radix(hex, 16).ok()
            } else {
                value.parse().ok()
            }
        }
        _ => None,
    }
}

fn tables<'a>(table: &'a Table, key: &str, limit: usize) -> Option<Vec<&'a Table>> {
    let Some(value) = table.get(key) else {
        return Some(Vec::new());
    };
    let values = value.as_array()?;
    if values.len() > limit {
        return None;
    }
    values.iter().map(Value::as_table).collect()
}

pub(super) fn manifest(root: &Table) -> Option<(PackageManifest, Option<String>, Vec<String>)> {
    let mut selected = None;
    for key in ["package", "service", "driver"] {
        if let Some(value) = root.get(key) {
            if selected.is_some() {
                return None;
            }
            selected = Some((key, value.as_table()?));
        }
    }
    let (kind, package) = selected?;
    let legacy_entry = if kind == "package" {
        None
    } else {
        optional_string(package, "entry")?
    };
    let legacy_requires = match root.get("capabilities") {
        None => Vec::new(),
        Some(value) => requirements(value.as_table()?)?,
    };
    let mut result = PackageManifest {
        package_id: string(package, "id")?,
        package_name: string(package, "name")?,
        package_version: string(package, "version")?,
        install_provenance: optional_string(package, "provenance")?,
        vendor: alias(package, "vendor", "developer")?,
        package_kind: optional_string(package, "kind")?,
        package_architecture: optional_string(package, "architecture")?,
        package_abi: optional_string(package, "abi")?,
        interactive_capabilities: match root.get("prompt") {
            None => Vec::new(),
            Some(value) => capability_list(value.as_table()?, "interactive_capabilities")?,
        },
        ..PackageManifest::default()
    };
    for table in tables(root, "binary", MAX_ENTRIES)? {
        result.binaries.push(PackageBinary {
            path: alias(table, "path", "entry")?.unwrap_or_default(),
            file: optional_string(table, "file")?,
            capability_profile: optional_string(table, "capability_profile")?,
            requires: requirements(table)?,
            resource_exports: strings(table, "resource_exports", MAX_REQUIREMENTS)?,
            resource_dependencies: strings(table, "resource_dependencies", MAX_REQUIREMENTS)?,
            kind: optional_string(table, "kind")?,
            driver_class: optional_string(table, "driver_class")?,
            api_version: match table.get("api_version") {
                None => None,
                Some(value) => Some(u32::try_from(number(value)?).ok()?),
            },
            match_bus: optional_string(table, "match_bus")?,
            match_class: optional_string(table, "match_class")?,
            match_vendor_id: optional_string(table, "match_vendor_id")?,
            match_device_id: optional_string(table, "match_device_id")?,
        });
    }
    if !result.binaries.is_empty() && (legacy_entry.is_some() || !legacy_requires.is_empty()) {
        return None;
    }
    for table in tables(root, "file", MAX_ENTRIES)? {
        let mode = match table.get("mode")? {
            Value::String(value) => value.clone(),
            Value::Integer(value) if *value >= 0 => value.to_string(),
            _ => return None,
        };
        if mode.is_empty() || mode.len() > 4 {
            return None;
        }
        result.files.push(PackageFile {
            id: string(table, "id")?,
            path: string(table, "path")?,
            digest: string(table, "digest")?,
            size: number(table.get("size")?)?,
            mode: u32::from_str_radix(&mode, 8).ok()?,
        });
    }
    for table in tables(root, "library_dependency", 256)? {
        if table.keys().any(|key| {
            ![
                "package",
                "developer",
                "subject_key_id",
                "provenance",
                "abi",
            ]
            .contains(&key.as_str())
        }) {
            return None;
        }
        result.library_dependencies.push(LibraryDependency {
            package: string(table, "package")?,
            developer: string(table, "developer")?,
            subject_key_id: string(table, "subject_key_id")?,
            provenance: string(table, "provenance")?,
            abi: string(table, "abi")?,
        });
    }
    for table in tables(root, "resource_export", 256)? {
        if table
            .keys()
            .any(|key| !["name", "files"].contains(&key.as_str()))
        {
            return None;
        }
        let bindings = table.get("files")?.as_table()?;
        if bindings.len() > MAX_ENTRIES {
            return None;
        }
        let files = bindings
            .iter()
            .map(|(name, value)| {
                Some(ResourceFile {
                    name: name.clone(),
                    file: value.as_str()?.into(),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        result.resource_exports.push(ResourceExport {
            name: string(table, "name")?,
            files,
        });
    }
    for table in tables(root, "resource_dependency", 256)? {
        if table.keys().any(|key| {
            ![
                "alias",
                "package",
                "developer",
                "subject_key_id",
                "provenance",
                "abi",
                "export",
            ]
            .contains(&key.as_str())
        }) {
            return None;
        }
        result.resource_dependencies.push(ResourceDependency {
            alias: string(table, "alias")?,
            export: string(table, "export")?,
            provider: LibraryDependency {
                package: string(table, "package")?,
                developer: string(table, "developer")?,
                subject_key_id: string(table, "subject_key_id")?,
                provenance: string(table, "provenance")?,
                abi: string(table, "abi")?,
            },
        });
    }
    if let Some(value) = root.get("application") {
        let table = value.as_table()?;
        result.application = Some(ApplicationMetadata {
            entry: string(table, "entry")?,
            description: string(table, "description")?,
            icon: string(table, "icon")?,
            resources: strings(table, "resources", MAX_ENTRIES)?,
        });
    }
    if let Some(value) = root.get("linux") {
        let table = value.as_table()?;
        result.linux = Some(LinuxApplication {
            entrypoint: string(table, "entrypoint")?,
            rootfs_file: string(table, "rootfs_file")?,
            writable_paths: strings(table, "writable_paths", MAX_ENTRIES)?,
            portal_read_paths: strings(table, "portal_read_paths", MAX_ENTRIES)?,
            portal_write_paths: strings(table, "portal_write_paths", MAX_ENTRIES)?,
            network: optional_string(table, "network")?,
        });
    }
    Some((result, legacy_entry, legacy_requires))
}
