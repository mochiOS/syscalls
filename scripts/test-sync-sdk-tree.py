#!/usr/bin/env python3
"""Regression checks for SDK inputs used by Cargo's incremental build."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
import sys

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location('sync_sdk_tree', Path(__file__).with_name('sync-sdk-tree.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
lock_spec = importlib.util.spec_from_file_location('cargo_preserve_lock', Path(__file__).with_name('cargo-preserve-lock.py'))
lock_module = importlib.util.module_from_spec(lock_spec)
lock_spec.loader.exec_module(lock_module)


class SDKTreeTest(unittest.TestCase):
    def test_cargo_unused_diagnostics_do_not_change_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = Path(tmp) / 'Cargo.lock'
            resolved = 'version = 4\n[[package]]\nname="active"\nversion="1"\n'
            first = resolved + '[[patch.unused]]\nname="a"\nversion="1"\n'
            second = '[[patch.unused]]\nname="b"\nversion="2"\n'
            lock.write_text(first + second)
            before = lock.stat().st_mtime_ns
            changed = resolved + second + first[len(resolved):]
            command = [sys.executable, '-c', 'import pathlib,sys; pathlib.Path(sys.argv[1]).write_text(sys.argv[2])', str(lock), changed]
            self.assertEqual(lock_module.run(lock, command), 0)
            self.assertEqual(lock.read_text(), first + second)
            self.assertEqual(lock.stat().st_mtime_ns, before)
            command[-1] = resolved
            self.assertEqual(lock_module.run(lock, command), 0)
            self.assertEqual(lock.read_text(), first + second)
            # Real dependency changes and command failures must remain visible.
            command[-1] = changed.replace('name="active"\nversion="1"', 'name="active"\nversion="3"')
            command[2] += '; sys.exit(7)'
            self.assertEqual(lock_module.run(lock, command), 7)
            self.assertIn('version="3"', lock.read_text())

    def test_reinstall_identical_bytes_keeps_watched_inode_and_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp) / 'prepared', Path(tmp) / 'sdk'
            (source / 'lib').mkdir(parents=True)
            library = source / 'lib/libc.a'
            library.write_bytes(b'library version 1')
            module.sync(source, target)
            installed = target / 'lib/libc.a'
            before = installed.stat()
            library.write_bytes(b'library version 1')
            os.utime(library, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
            module.sync(source, target)
            after = installed.stat()
            self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))
            # Equal size/time must not hide a real update.
            library.write_bytes(b'library version 2')
            os.utime(library, ns=(before.st_atime_ns, before.st_mtime_ns))
            module.sync(source, target)
            self.assertEqual(installed.read_bytes(), b'library version 2')

    def test_removed_headers_modes_links_and_type_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp) / 'prepared', Path(tmp) / 'sdk'
            source.mkdir()
            (source / 'header').write_text('old')
            (source / 'alias').symlink_to('header')
            module.sync(source, target)
            (source / 'header').unlink()
            (source / 'header').mkdir()
            (source / 'header/new').write_text('new')
            (source / 'header/new').chmod(0o600)
            (source / 'alias').unlink()
            (source / 'alias').write_text('regular')
            module.sync(source, target)
            self.assertTrue((target / 'header').is_dir())
            self.assertEqual((target / 'header/new').stat().st_mode & 0o777, 0o600)
            self.assertFalse((target / 'alias').is_symlink())
            (source / 'header/new').unlink()
            module.sync(source, target)
            self.assertFalse((target / 'header/new').exists())


if __name__ == '__main__':
    unittest.main()
