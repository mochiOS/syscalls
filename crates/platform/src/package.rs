use crate::syscall::{NativeError, SysError};
use NativeError::{InvalidArgument, LimitExceeded, ResourceUnavailable};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub use crate::native_mpkg_reader::NativeMpkgReader;

const MPKG_HEADER_LEN: u64 = 32;
const TAR_BLOCK_LEN: u64 = 512;
const MAX_MPKG_LEN: u64 = 256 * 1024 * 1024;
const MAX_MPKG_ENTRIES: usize = 4096;
const MAX_MANIFEST_LEN: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct MpkgEntry {
    pub path: String,
    pub kind: u8,
    pub size: u64,
    pub offset: u64,
}

#[derive(Clone, Debug)]
pub struct MpkgIndex {
    pub file_len: u64,
    pub manifest: Vec<u8>,
    pub entries: Vec<MpkgEntry>,
}

impl MpkgIndex {
    pub fn entry(&self, path: &str) -> Option<&MpkgEntry> {
        self.entries.iter().find(|entry| entry.path == path)
    }
}

/// Random-access input used by the package parser.
///
/// Opening paths and owning descriptors are deliberately outside this trait;
/// callers may back it with a native Handle, an IPC object, or a test buffer.
pub trait MpkgReader {
    fn len(&mut self) -> Result<u64, SysError>;
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), SysError>;
}

fn package_error(error: NativeError) -> SysError {
    SysError::from_raw(error.into_raw() as i64)
}

pub fn index_mpkg_reader(reader: &mut impl MpkgReader) -> Result<MpkgIndex, SysError> {
    let file_len = reader.len()?;
    if file_len < MPKG_HEADER_LEN {
        return Err(package_error(InvalidArgument));
    }
    if file_len > MAX_MPKG_LEN {
        return Err(package_error(LimitExceeded));
    }
    let mut header = [0u8; MPKG_HEADER_LEN as usize];
    reader.read_exact_at(0, &mut header)?;
    if &header[..4] != b"MPKG"
        || u16::from_le_bytes([header[4], header[5]]) != 1
        || u16::from_le_bytes([header[6], header[7]]) != 0
        || u16::from_le_bytes([header[8], header[9]]) != MPKG_HEADER_LEN as u16
        || header[10] != 0
        || header[11] != 0
        || header[20..].iter().any(|byte| *byte != 0)
    {
        return Err(package_error(InvalidArgument));
    }
    let expanded = u64::from_le_bytes(header[12..20].try_into().unwrap());
    if expanded != file_len - MPKG_HEADER_LEN {
        return Err(package_error(InvalidArgument));
    }

    let mut entries = Vec::new();
    let mut manifest = None;
    let mut offset = MPKG_HEADER_LEN;
    let mut terminated = false;
    while offset + TAR_BLOCK_LEN <= file_len {
        let mut block = [0u8; TAR_BLOCK_LEN as usize];
        reader.read_exact_at(offset, &mut block)?;
        if block.iter().all(|byte| *byte == 0) {
            if !range_is_zero(reader, offset, file_len - offset)? {
                return Err(package_error(InvalidArgument));
            }
            terminated = true;
            break;
        }
        if entries.len() >= MAX_MPKG_ENTRIES {
            return Err(package_error(LimitExceeded));
        }
        if &block[257..263] != b"ustar\0" || &block[263..265] != b"00" {
            return Err(package_error(InvalidArgument));
        }
        let expected_checksum =
            parse_tar_octal(&block[148..156]).ok_or(package_error(InvalidArgument))?;
        let checksum: u64 = block
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                u64::from(if (148..156).contains(&index) {
                    b' '
                } else {
                    *byte
                })
            })
            .sum();
        if expected_checksum != checksum {
            return Err(package_error(InvalidArgument));
        }
        let name = tar_text(&block[..100]).ok_or(package_error(InvalidArgument))?;
        let prefix = tar_text(&block[345..500]).ok_or(package_error(InvalidArgument))?;
        let path = if prefix.is_empty() {
            name
        } else {
            alloc::format!("{prefix}/{name}")
        };
        if !valid_mpkg_path(&path) || entries.iter().any(|entry: &MpkgEntry| entry.path == path) {
            return Err(package_error(InvalidArgument));
        }
        let kind = block[156];
        if kind != 0 && kind != b'0' && kind != b'5' {
            return Err(package_error(InvalidArgument));
        }
        let size = parse_tar_octal(&block[124..136]).ok_or(package_error(InvalidArgument))?;
        let data_offset = offset
            .checked_add(TAR_BLOCK_LEN)
            .ok_or(package_error(LimitExceeded))?;
        let data_end = data_offset
            .checked_add(size)
            .ok_or(package_error(LimitExceeded))?;
        if data_end > file_len {
            return Err(package_error(InvalidArgument));
        }
        if path == "manifest.toml" {
            if size > MAX_MANIFEST_LEN || kind == b'5' {
                return Err(package_error(InvalidArgument));
            }
            let mut data = Vec::new();
            data.try_reserve_exact(size as usize)
                .map_err(|_| package_error(ResourceUnavailable))?;
            data.resize(size as usize, 0);
            reader.read_exact_at(data_offset, &mut data)?;
            manifest = Some(data);
        }
        entries.push(MpkgEntry {
            path,
            kind,
            size,
            offset: data_offset,
        });
        let padded = size
            .checked_add(511)
            .ok_or(package_error(LimitExceeded))?
            / 512
            * 512;
        offset = data_offset
            .checked_add(padded)
            .ok_or(package_error(LimitExceeded))?;
    }
    if !terminated {
        return Err(package_error(InvalidArgument));
    }
    let manifest = manifest.ok_or(package_error(InvalidArgument))?;
    Ok(MpkgIndex {
        file_len,
        manifest,
        entries,
    })
}

pub fn read_mpkg_range_reader(
    reader: &mut impl MpkgReader,
    offset: u64,
    size: u64,
) -> Result<Vec<u8>, SysError> {
    let end = offset.checked_add(size).ok_or(package_error(LimitExceeded))?;
    if end > reader.len()? {
        return Err(package_error(InvalidArgument));
    }
    let size = usize::try_from(size).map_err(|_| package_error(LimitExceeded))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| package_error(ResourceUnavailable))?;
    bytes.resize(size, 0);
    reader.read_exact_at(offset, &mut bytes)?;
    Ok(bytes)
}

fn range_is_zero(
    reader: &mut impl MpkgReader,
    offset: u64,
    length: u64,
) -> Result<bool, SysError> {
    let mut remaining = length;
    let mut cursor = offset;
    let mut buffer = [0u8; 4096];
    while remaining > 0 {
        let requested = core::cmp::min(remaining, buffer.len() as u64) as usize;
        reader.read_exact_at(cursor, &mut buffer[..requested])?;
        if buffer[..requested].iter().any(|byte| *byte != 0) {
            return Ok(false);
        }
        remaining -= requested as u64;
        cursor = cursor
            .checked_add(requested as u64)
            .ok_or(package_error(LimitExceeded))?;
    }
    Ok(true)
}

fn tar_text(bytes: &[u8]) -> Option<String> {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..length])
        .ok()
        .map(ToString::to_string)
}

fn parse_tar_octal(bytes: &[u8]) -> Option<u64> {
    let mut value = 0u64;
    let mut seen = false;
    for byte in bytes {
        if *byte == 0 || *byte == b' ' {
            break;
        }
        if !(b'0'..=b'7').contains(byte) {
            return None;
        }
        seen = true;
        value = value.checked_mul(8)?.checked_add(u64::from(*byte - b'0'))?;
    }
    seen.then_some(value)
}

fn valid_mpkg_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains("//")
        && !path.ends_with('/')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && (path == "manifest.toml"
            || path.starts_with("signatures/")
            || path.starts_with("payload/"))
}

pub use mochios_package_manifest::{
    ApplicationMetadata, LibraryDependency, LinuxApplication, PackageBinary, PackageFile,
    ResourceDependency, ResourceExport, ResourceFile,
    PackageManifest, parse_manifest,
};

pub fn binary_requires<'a>(manifest: &'a PackageManifest, path: &str) -> Option<&'a [String]> {
    manifest.binary_requires(path)
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
    fn parses_linux_application_manifest() {
        let manifest = parse_manifest(
            r#"
            [package]
            id = "org.example.editor"
            name = "Editor"
            version = "1"
            kind = "application"
            architecture = "x86_64"
            abi = "mboot-linux-1"

            [application]
            entry = "linux:org.example.editor"
            description = "Editor"
            icon = ""
            resources = []

            [linux]
            entrypoint = "/usr/bin/editor"
            rootfs_file = "linux-rootfs"
            writable_paths = [
                "/usr/share/editor",
                "/var/lib/editor",
            ]
            portal_read_paths = ["/applications", "/home/$USER/Develop"]
            portal_write_paths = ["/home/$USER/Develop"]
            network = "client"

            [[file]]
            id = "linux-rootfs"
            path = "$/rootfs.squashfs"
            digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            size = 4096
            mode = "0644"
            "#,
        )
        .unwrap();
        let linux = manifest.linux.unwrap();
        assert_eq!(linux.entrypoint, "/usr/bin/editor");
        assert_eq!(linux.rootfs_file, "linux-rootfs");
        assert_eq!(
            linux.writable_paths,
            ["/usr/share/editor", "/var/lib/editor"]
        );
        assert_eq!(
            linux.portal_read_paths,
            ["/applications", "/home/$USER/Develop"]
        );
        assert_eq!(linux.portal_write_paths, ["/home/$USER/Develop"]);
        assert_eq!(linux.network.as_deref(), Some("client"));
    }

    #[test]
    fn rejects_unsafe_linux_portal_paths() {
        for (key, path) in [
            ("portal_read_paths", "/system"),
            ("portal_read_paths", "/home/alice"),
            ("portal_write_paths", "/applications"),
            ("portal_write_paths", "/home/$USER/../root"),
        ] {
            let manifest = alloc::format!(
                r#"
                [package]
                id = "org.example.editor"
                name = "Editor"
                version = "1"
                kind = "application"
                abi = "mboot-linux-1"
                [linux]
                entrypoint = "/usr/bin/editor"
                rootfs_file = "linux-rootfs"
                {key} = ["{path}"]
                [[file]]
                id = "linux-rootfs"
                path = "$/rootfs.squashfs"
                digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                size = 4096
                mode = "0644"
            "#
            );
            assert!(parse_manifest(&manifest).is_none(), "accepted {key}={path}");
        }
    }

    #[test]
    fn rejects_unsafe_linux_writable_paths_and_missing_rootfs() {
        for (rootfs_file, writable) in [
            ("missing", "/var/lib/editor"),
            ("linux-rootfs", "/usr/bin/editor"),
            ("linux-rootfs", "/mochios/system"),
            ("linux-rootfs", "/home/user"),
            ("linux-rootfs", "/proc/self"),
            ("linux-rootfs", "/var/../system"),
        ] {
            let text = alloc::format!(
                r#"
                [package]
                id = "org.example.editor"
                name = "Editor"
                version = "1"
                kind = "application"
                abi = "mboot-linux-1"

                [linux]
                entrypoint = "/usr/bin/editor"
                rootfs_file = "{rootfs_file}"
                writable_paths = ["{writable}"]

                [[file]]
                id = "linux-rootfs"
                path = "$/rootfs.squashfs"
                digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                size = 4096
                mode = "0644"
                "#
            );
            assert!(parse_manifest(&text).is_none());
        }
        let overlapping = r#"
            [package]
            id = "org.example.editor"
            name = "Editor"
            version = "1"
            kind = "application"
            abi = "mboot-linux-1"
            [linux]
            entrypoint = "/usr/bin/editor"
            rootfs_file = "linux-rootfs"
            writable_paths = ["/var/lib/editor", "/var/lib/editor/cache"]
            [[file]]
            id = "linux-rootfs"
            path = "$/rootfs.squashfs"
            digest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            size = 4096
            mode = "0644"
        "#;
        assert!(parse_manifest(overlapping).is_none());
    }

    #[test]
    fn parses_multiline_legacy_capabilities_requires() {
        let manifest = r#"
            [service]
            id = "org.mochios.logger"
            name = "Logger Service"
            version = "1"
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
