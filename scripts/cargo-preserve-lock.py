#!/usr/bin/env python3
"""Keep Cargo's unused-patch reordering from invalidating native builds."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib


def semantic_lock(data):
    """Ignore only the unordered list of unused patches, not dependencies."""
    value = tomllib.loads(data.decode())
    unused = value.get('patch', {}).get('unused', [])
    unused.sort(key=lambda entry: tuple(sorted(entry.items())))
    return value


def run(lock, command):
    before = lock.read_bytes() if lock.exists() else None
    metadata = lock.stat() if before is not None else None
    result = subprocess.run(command)
    if before is not None and lock.is_file():
        after = lock.read_bytes()
        if after != before and semantic_lock(before) == semantic_lock(after):
            descriptor, name = tempfile.mkstemp(prefix='.cargo-lock-', dir=lock.parent)
            try:
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(before)
                os.chmod(name, metadata.st_mode & 0o777)
                os.utime(name, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
                os.replace(name, lock)
            finally:
                Path(name).unlink(missing_ok=True)
    return result.returncode


def workspace_lock(command):
    """Ask Cargo for the owning workspace instead of guessing member paths."""
    index = command.index('--manifest-path')
    manifest = command[index + 1]
    workspace = subprocess.check_output([
        'cargo', 'locate-project', '--workspace', '--message-format', 'plain',
        '--manifest-path', manifest,
    ], text=True).strip()
    return Path(workspace).with_name('Cargo.lock')


if __name__ == '__main__':
    if len(sys.argv) < 4 or sys.argv[2] != '--':
        raise SystemExit('usage: cargo-preserve-lock.py <Cargo.lock> -- <cargo command>')
    command = sys.argv[3:]
    lock = workspace_lock(command) if sys.argv[1] == '--auto' else Path(sys.argv[1])
    raise SystemExit(run(lock, command))
