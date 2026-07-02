use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Clone, Debug, Default)]
pub struct PackageBinary {
    pub path: String,
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
pub struct PackageManifest {
    pub package_id: String,
    pub package_name: String,
    pub package_version: String,
    pub vendor: Option<String>,
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

fn parse_array_values(value: &str) -> Option<Vec<String>> {
    let value = value.trim();
    let inner = value.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for item in inner.split(',') {
        let trimmed = item.trim();
        let unquoted = trimmed.strip_prefix('"')?.strip_suffix('"')?;
        out.push(unquoted.to_string());
    }
    Some(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Package,
    Binary,
    LegacyPackage,
    LegacyCapabilities,
}

pub fn parse_manifest(text: &str) -> Option<PackageManifest> {
    let mut section = Section::None;
    let mut package = PackageManifest::default();
    let mut current_binary: Option<PackageBinary> = None;
    let mut legacy_entry: Option<String> = None;
    let mut legacy_requires: Vec<String> = Vec::new();

    let push_binary = |current_binary: &mut Option<PackageBinary>, binaries: &mut Vec<PackageBinary>| {
        if let Some(binary) = current_binary.take() {
            binaries.push(binary);
        }
    };

    for raw in text.lines() {
        let line = trim_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[binary]]" {
            push_binary(&mut current_binary, &mut package.binaries);
            current_binary = Some(PackageBinary::default());
            section = Section::Binary;
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            push_binary(&mut current_binary, &mut package.binaries);
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
                "entry" if section == Section::LegacyPackage => {
                    legacy_entry = Some(unquote(value).unwrap_or_else(|| value.to_string()))
                }
                _ => {}
            },
            Section::Binary => {
                let binary = current_binary.as_mut()?;
                match key {
                    "path" => binary.path = unquote(value).unwrap_or_else(|| value.to_string()),
                    "capability_profile" => {
                        binary.capability_profile =
                            Some(unquote(value).unwrap_or_else(|| value.to_string()))
                    }
                    "kind" => binary.kind = Some(unquote(value).unwrap_or_else(|| value.to_string())),
                    "driver_class" => {
                        binary.driver_class = Some(unquote(value).unwrap_or_else(|| value.to_string()))
                    }
                    "api_version" => binary.api_version = parse_u32_like(value),
                    "match_bus" => {
                        binary.match_bus = Some(unquote(value).unwrap_or_else(|| value.to_string()))
                    }
                    "match_class" => {
                        binary.match_class = Some(unquote(value).unwrap_or_else(|| value.to_string()))
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
                        binary.requires = parse_array_values(value)?;
                    }
                    "entry" if binary.path.is_empty() => {
                        binary.path = unquote(value).unwrap_or_else(|| value.to_string())
                    }
                    _ => {}
                }
            }
            Section::None => {}
            Section::LegacyCapabilities => {
                if key == "requires" {
                    legacy_requires = parse_array_values(value)?;
                }
            }
        }
    }

    push_binary(&mut current_binary, &mut package.binaries);

    if package.package_id.is_empty()
        || package.package_name.is_empty()
        || package.package_version.is_empty()
    {
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
