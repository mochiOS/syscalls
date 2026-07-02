use alloc::string::{String, ToString};
use alloc::vec::Vec;

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

#[derive(Clone, Debug, Default)]
pub struct PackageManifest {
    pub package_id: String,
    pub package_name: String,
    pub package_version: String,
    pub vendor: Option<String>,
    pub package_kind: Option<String>,
    pub package_architecture: Option<String>,
    pub package_abi: Option<String>,
    pub files: Vec<PackageFile>,
    pub binaries: Vec<PackageBinary>,
}

impl PackageManifest {
    pub fn binary(&self, path: &str) -> Option<&PackageBinary> {
        self.binaries.iter().find(|binary| binary.path == path)
    }

    pub fn binary_requires(&self, path: &str) -> Option<&[String]> {
        self.binary(path).map(|binary| binary.requires.as_slice())
    }
}

fn trim_comment(line: &str) -> &str {
    let mut in_string = false;
    let mut escape = false;
    for (idx, ch) in line.char_indices() {
        match ch {
            '"' if !escape => in_string = !in_string,
            '#' if !in_string => return line[..idx].trim_end(),
            '\\' if !escape => escape = true,
            _ => escape = false,
        }
    }
    line.trim_end()
}

fn split_kv(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    Some((key.trim(), value.trim()))
}

fn unquote(value: &str) -> Option<String> {
    let value = value.trim();
    if !value.starts_with('"') || !value.ends_with('"') || value.len() < 2 {
        return None;
    }
    let mut out = String::new();
    let mut chars = value[1..value.len() - 1].chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next()? {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            other => out.push(other),
        }
    }
    Some(out)
}

fn parse_u32_like(value: &str) -> Option<u32> {
    let value = if value.trim().starts_with('"') {
        unquote(value)?
    } else {
        value.trim().to_string()
    };
    if let Some(hex) = value.strip_prefix("0x") {
        return u32::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = value.strip_prefix("0X") {
        return u32::from_str_radix(hex, 16).ok();
    }
    value.parse::<u32>().ok()
}

fn parse_u64_like(value: &str) -> Option<u64> {
    let value = if value.trim().starts_with('"') {
        unquote(value)?
    } else {
        value.trim().to_string()
    };
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    value.parse::<u64>().ok()
}

fn parse_octal_mode(value: &str) -> Option<u32> {
    let value = if value.trim().starts_with('"') {
        unquote(value)?
    } else {
        value.trim().to_string()
    };
    if value.is_empty() || value.len() > 4 {
        return None;
    }
    u32::from_str_radix(&value, 8).ok()
}

fn parse_array_values(value: &str) -> Option<Vec<String>> {
    let value = value.trim();
    let inner = value.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for item in inner.split(',') {
        let trimmed = item.trim().trim_end_matches(']').trim();
        if trimmed.is_empty() {
            continue;
        }
        let unquoted = trimmed.strip_prefix('"')?.strip_suffix('"')?;
        out.push(unquoted.to_string());
    }
    Some(out)
}

fn is_valid_package_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Package,
    Binary,
    File,
    LegacyPackage,
    LegacyCapabilities,
}

pub fn parse_manifest(text: &str) -> Option<PackageManifest> {
    let mut section = Section::None;
    let mut package = PackageManifest::default();
    let mut current_binary: Option<PackageBinary> = None;
    let mut current_file: Option<PackageFile> = None;
    let mut legacy_entry: Option<String> = None;
    let mut legacy_requires: Vec<String> = Vec::new();
    let mut pending_array: Option<(Section, String, String)> = None;

    let push_binary = |current_binary: &mut Option<PackageBinary>,
                       binaries: &mut Vec<PackageBinary>| {
        if let Some(binary) = current_binary.take() {
            binaries.push(binary);
        }
    };
    let push_file = |current_file: &mut Option<PackageFile>, files: &mut Vec<PackageFile>| {
        if let Some(file) = current_file.take() {
            files.push(file);
        }
    };

    for raw in text.lines() {
        let line = trim_comment(raw).trim();
        if line.is_empty() {
            continue;
        }

        if let Some((pending_section, pending_key, pending_value)) = pending_array.as_mut() {
            if !pending_value.is_empty() {
                pending_value.push(' ');
            }
            pending_value.push_str(line);
            if !line.contains(']') {
                continue;
            }

            let collected = pending_value.clone();
            let parsed = parse_array_values(&collected)?;
            match pending_section {
                Section::Binary => {
                    let binary = current_binary.as_mut()?;
                    match pending_key.as_str() {
                        "requires" => binary.requires = parsed,
                        _ => {}
                    }
                }
                Section::LegacyCapabilities => match pending_key.as_str() {
                    "requires" => legacy_requires = parsed,
                    _ => {}
                },
                _ => {}
            }
            pending_array = None;
            continue;
        }

        if line == "[[binary]]" {
            push_binary(&mut current_binary, &mut package.binaries);
            push_file(&mut current_file, &mut package.files);
            current_binary = Some(PackageBinary::default());
            section = Section::Binary;
            continue;
        }
        if line == "[[file]]" {
            push_binary(&mut current_binary, &mut package.binaries);
            push_file(&mut current_file, &mut package.files);
            current_file = Some(PackageFile::default());
            section = Section::File;
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            push_binary(&mut current_binary, &mut package.binaries);
            push_file(&mut current_file, &mut package.files);
            section = match &line[1..line.len() - 1] {
                "package" => Section::Package,
                "service" | "driver" => Section::LegacyPackage,
                "capabilities" => Section::LegacyCapabilities,
                _ => Section::None,
            };
            continue;
        }

        let Some((key, value)) = split_kv(line) else {
            continue;
        };

        match section {
            Section::Package | Section::LegacyPackage => match key {
                "id" => package.package_id = unquote(value).unwrap_or_else(|| value.to_string()),
                "name" => {
                    package.package_name = unquote(value).unwrap_or_else(|| value.to_string())
                }
                "version" => {
                    package.package_version = unquote(value).unwrap_or_else(|| value.to_string())
                }
                "vendor" | "developer" => {
                    package.vendor = Some(unquote(value).unwrap_or_else(|| value.to_string()))
                }
                "kind" => {
                    package.package_kind = Some(unquote(value).unwrap_or_else(|| value.to_string()))
                }
                "architecture" => {
                    package.package_architecture =
                        Some(unquote(value).unwrap_or_else(|| value.to_string()))
                }
                "abi" => {
                    package.package_abi = Some(unquote(value).unwrap_or_else(|| value.to_string()))
                }
                "entry" if section == Section::LegacyPackage => {
                    legacy_entry = Some(unquote(value).unwrap_or_else(|| value.to_string()))
                }
                _ => {}
            },
            Section::Binary => {
                let binary = current_binary.as_mut()?;
                match key {
                    "path" => binary.path = unquote(value).unwrap_or_else(|| value.to_string()),
                    "file" => {
                        binary.file = Some(unquote(value).unwrap_or_else(|| value.to_string()))
                    }
                    "capability_profile" => {
                        binary.capability_profile =
                            Some(unquote(value).unwrap_or_else(|| value.to_string()))
                    }
                    "kind" => {
                        binary.kind = Some(unquote(value).unwrap_or_else(|| value.to_string()))
                    }
                    "driver_class" => {
                        binary.driver_class =
                            Some(unquote(value).unwrap_or_else(|| value.to_string()))
                    }
                    "api_version" => binary.api_version = parse_u32_like(value),
                    "match_bus" => {
                        binary.match_bus = Some(unquote(value).unwrap_or_else(|| value.to_string()))
                    }
                    "match_class" => {
                        binary.match_class =
                            Some(unquote(value).unwrap_or_else(|| value.to_string()))
                    }
                    "match_vendor_id" => {
                        binary.match_vendor_id =
                            Some(unquote(value).unwrap_or_else(|| value.to_string()))
                    }
                    "match_device_id" => {
                        binary.match_device_id =
                            Some(unquote(value).unwrap_or_else(|| value.to_string()))
                    }
                    "requires" => {
                        if value.trim_start().starts_with('[') && !value.contains(']') {
                            pending_array = Some((section, key.to_string(), value.to_string()));
                            continue;
                        }
                        binary.requires = parse_array_values(value)?;
                    }
                    "entry" if binary.path.is_empty() => {
                        binary.path = unquote(value).unwrap_or_else(|| value.to_string())
                    }
                    _ => {}
                }
            }
            Section::File => {
                let file = current_file.as_mut()?;
                match key {
                    "id" => file.id = unquote(value).unwrap_or_else(|| value.to_string()),
                    "path" => file.path = unquote(value).unwrap_or_else(|| value.to_string()),
                    "digest" => file.digest = unquote(value).unwrap_or_else(|| value.to_string()),
                    "size" => file.size = parse_u64_like(value)?,
                    "mode" => file.mode = parse_octal_mode(value)?,
                    _ => {}
                }
            }
            Section::None => {}
            Section::LegacyCapabilities => {
                if key == "requires" {
                    if value.trim_start().starts_with('[') && !value.contains(']') {
                        pending_array = Some((section, key.to_string(), value.to_string()));
                        continue;
                    }
                    legacy_requires = parse_array_values(value)?;
                }
            }
        }
    }

    push_binary(&mut current_binary, &mut package.binaries);
    push_file(&mut current_file, &mut package.files);

    if package.package_id.is_empty()
        || package.package_name.is_empty()
        || package.package_version.is_empty()
    {
        return None;
    }
    if !is_valid_package_id(&package.package_id) {
        return None;
    }

    if package.binaries.is_empty() {
        if let Some(entry) = legacy_entry {
            package.binaries.push(PackageBinary {
                path: entry,
                requires: legacy_requires,
                ..PackageBinary::default()
            });
        }
    }

    for binary in &package.binaries {
        if binary.path.is_empty() {
            return None;
        }
    }

    for (idx, left) in package.binaries.iter().enumerate() {
        for right in package.binaries.iter().skip(idx + 1) {
            if left.path == right.path {
                return None;
            }
        }
    }

    for file in &package.files {
        if file.id.is_empty() || file.path.is_empty() || file.digest.is_empty() || file.mode == 0 {
            return None;
        }
    }
    for (idx, left) in package.files.iter().enumerate() {
        for right in package.files.iter().skip(idx + 1) {
            if left.id == right.id || left.path == right.path {
                return None;
            }
        }
    }

    Some(package)
}

pub fn binary_requires<'a>(manifest: &'a PackageManifest, path: &str) -> Option<&'a [String]> {
    manifest.binary_requires(path)
}

pub fn read_manifest(path: &str) -> Option<PackageManifest> {
    let bytes = crate::file::read_to_end_path(path).ok()?;
    let text = core::str::from_utf8(&bytes).ok()?;
    parse_manifest(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiline_binary_requires() {
        let manifest = r#"
            [package]
            id = "org.mochios.logger"
            name = "Logger Service"
            version = "1"

            [[binary]]
            path = "/system/services/logger.service"
            kind = "service"
            requires = [
                "fs.write.all",
                "ipc.client",
                "ipc.server",
            ]
        "#;

        let parsed = parse_manifest(manifest).expect("manifest should parse");
        assert_eq!(parsed.package_id, "org.mochios.logger");
        assert_eq!(parsed.binaries.len(), 1);
        assert_eq!(
            parsed
                .binary("/system/services/logger.service")
                .unwrap()
                .requires
                .len(),
            3
        );
        assert_eq!(
            parsed
                .binary("/system/services/logger.service")
                .unwrap()
                .requires[0],
            "fs.write.all"
        );
    }

    #[test]
    fn parses_multiline_legacy_capabilities_requires() {
        let manifest = r#"
            [service]
            entry = "/system/services/logger.service"

            [capabilities]
            requires = [
                "fs.write.all",
                "ipc.client",
            ]
        "#;

        let parsed = parse_manifest(manifest).expect("manifest should parse");
        assert_eq!(parsed.binaries.len(), 1);
        assert_eq!(parsed.binaries[0].path, "/system/services/logger.service");
        assert_eq!(parsed.binaries[0].requires.len(), 2);
    }
}
