import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location("sdk", Path(__file__).with_name("rust-sdk.py"))
sdk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdk)


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "sdk.zip"
        self.destination = self.root / "SDK with spaces"

    def archive_with(self, *entries):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr("sdk.json", json.dumps({
                "format": 1, "target": sdk.TARGET, "toolchain": "nightly-2026-07-16",
                "compiler_commit": "a" * 40,
            }))
            for name, contents in entries:
                archive.writestr(name, contents)

    def test_install_local_archive(self):
        self.archive_with(("lib/example.a", "test"))
        sdk.install(argparse.Namespace(archive=self.archive, url=None,
                    sha256=sdk.checksum(self.archive), destination=self.destination))
        self.assertEqual((self.destination / "lib/example.a").read_text(), "test")

    def test_license_directory_preserves_component_notices(self):
        component = self.root / 'dependency'
        component.mkdir()
        (component / 'LICENSE.txt').write_text('license')
        (component / 'NOTICE').write_text('notice')
        (component / 'secret.key').write_text('not a license')
        self.assertEqual(set(sdk.license_files([component])), {
            'licenses/0-dependency/LICENSE.txt', 'licenses/0-dependency/NOTICE'})
        with self.assertRaisesRegex(ValueError, 'required'):
            sdk.license_files([])

    def test_checksum_mismatch_leaves_no_install(self):
        self.archive_with()
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            sdk.install(argparse.Namespace(archive=self.archive, url=None,
                        sha256="0" * 64, destination=self.destination))
        self.assertFalse(self.destination.exists())

    def test_unsafe_paths(self):
        for name in ("../escaped", "/absolute", "C:/absolute", "a\\b", "NUL.txt", "file."):
            with self.subTest(name=name):
                self.archive_with((name, "bad"))
                with self.assertRaises(ValueError):
                    sdk.unpack(self.archive, self.destination)
                self.assertFalse(self.destination.exists())

    def test_case_collision(self):
        self.archive_with(("file", "a"), ("FILE", "b"))
        with self.assertRaises(ValueError):
            sdk.unpack(self.archive, self.destination)

    def test_symlink(self):
        entry = zipfile.ZipInfo("link")
        entry.create_system = 3
        entry.external_attr = 0o120777 << 16
        self.archive_with((entry, "../../outside"))
        with self.assertRaises(ValueError):
            sdk.unpack(self.archive, self.destination)

    def test_existing_destination_untouched(self):
        self.archive_with()
        self.destination.mkdir()
        marker = self.destination / "existing"
        marker.write_text("keep")
        with self.assertRaises(ValueError):
            sdk.unpack(self.archive, self.destination)
        self.assertEqual(marker.read_text(), "keep")

    def test_existing_project_configuration_untouched(self):
        self.archive_with()
        sdk.unpack(self.archive, self.destination)
        project = self.root / "project"
        project.mkdir()
        (project / "Cargo.toml").write_text("[package]\n")
        marker = project / "rust-toolchain.toml"
        marker.write_text("keep")
        with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
            sdk.configure(argparse.Namespace(sdk=self.destination, project=project))
        self.assertEqual(marker.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
