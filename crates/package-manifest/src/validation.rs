use crate::PackageBinary;
use crate::PackageManifest;
use alloc::{string::String, vec::Vec};

pub(crate) fn is_valid_package_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
}

pub(crate) fn validate(
    mut package: PackageManifest,
    legacy_entry: Option<String>,
    legacy_requires: Vec<String>,
) -> Option<PackageManifest> {
    if package.package_id.is_empty()
        || package.package_name.is_empty()
        || package.package_version.is_empty()
    {
        return None;
    }
    if !is_valid_package_id(&package.package_id) {
        return None;
    }

    if package.package_kind.as_deref() == Some("application") {
        if package.package_name.len() > 64
            || matches!(package.package_name.as_str(), "." | "..")
            || package
                .package_name
                .bytes()
                .any(|byte| byte == b'/' || byte == b'\\' || byte == 0 || byte.is_ascii_control())
        {
            return None;
        }
        let application = package.application.as_ref()?;
        let valid_entry = if package.linux.is_some() {
            application.entry == alloc::format!("linux:{}", package.package_id)
        } else {
            is_valid_relative_bundle_path(&application.entry)
        };
        if !valid_entry
            || (!application.icon.is_empty() && !is_valid_relative_bundle_path(&application.icon))
            || application
                .resources
                .iter()
                .any(|path| !is_valid_relative_bundle_path(path))
        {
            return None;
        }
    }

    if package.binaries.is_empty()
        && let Some(entry) = legacy_entry
    {
        package.binaries.push(PackageBinary {
            path: entry,
            requires: legacy_requires,
            ..PackageBinary::default()
        });
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
    for (index, dependency) in package.library_dependencies.iter().enumerate() {
        if !dependency.valid()
            || package.library_dependencies[index + 1..]
                .iter()
                .any(|other| dependency.package == other.package)
        {
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

    if let Some(linux) = &package.linux {
        if package.package_kind.as_deref() != Some("application")
            || package.package_abi.as_deref() != Some("mboot-linux-1")
            || !is_valid_absolute_path(&linux.entrypoint)
            || linux.rootfs_file.is_empty()
            || !package
                .files
                .iter()
                .any(|file| file.id == linux.rootfs_file)
            || linux
                .writable_paths
                .iter()
                .any(|path| !is_valid_writable_linux_path(path))
            || linux
                .writable_paths
                .iter()
                .enumerate()
                .any(|(index, path)| {
                    linux.writable_paths[index + 1..]
                        .iter()
                        .any(|other| linux_paths_overlap(path, other))
                })
            || linux
                .portal_read_paths
                .iter()
                .any(|path| !is_valid_linux_portal_path(path, false))
            || linux
                .portal_write_paths
                .iter()
                .any(|path| !is_valid_linux_portal_path(path, true))
            || linux
                .network
                .as_deref()
                .is_some_and(|mode| mode != "client")
        {
            return None;
        }
    }

    Some(package)
}

fn is_valid_linux_portal_path(path: &str, writable: bool) -> bool {
    let user_home = path == "/home/$USER"
        || path.strip_prefix("/home/$USER/").is_some_and(|suffix| {
            !suffix.is_empty()
                && !suffix.contains('\\')
                && suffix
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != "..")
        });
    user_home
        || (!writable
            && (path == "/applications"
                || path.starts_with("/applications/")
                || path == "/libraries"
                || path.starts_with("/libraries/")))
}

fn linux_paths_overlap(left: &str, right: &str) -> bool {
    left == right
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn is_valid_absolute_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() > 1
        && !path.ends_with('/')
        && !path.contains("//")
        && !path.contains('\\')
        && !path.as_bytes().contains(&0)
        && path[1..]
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn is_valid_relative_bundle_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.ends_with('/')
        && !path.contains("//")
        && !path.contains('\\')
        && !path.as_bytes().contains(&0)
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn is_valid_writable_linux_path(path: &str) -> bool {
    is_valid_absolute_path(path)
        && !["/dev", "/proc", "/sys", "/run", "/tmp", "/home", "/mochios"]
            .iter()
            .any(|root| path == *root || path.starts_with(&alloc::format!("{root}/")))
        && !matches!(
            path,
            "/bin" | "/sbin" | "/lib" | "/lib64" | "/usr" | "/usr/bin" | "/usr/lib"
        )
        && !path.starts_with("/bin/")
        && !path.starts_with("/sbin/")
        && !path.starts_with("/lib/")
        && !path.starts_with("/lib64/")
        && !path.starts_with("/usr/bin/")
        && !path.starts_with("/usr/lib/")
        && !path.starts_with("/mochios")
}
