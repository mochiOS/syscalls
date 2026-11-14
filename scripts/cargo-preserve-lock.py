#!/usr/bin/env python3
"""Compatibility Cargo launcher. Never restore or overwrite Cargo's lock resolution."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib


def semantic_lock(data):
    """Ignore unused-patch diagnostics; retain the entire resolved package graph."""
    value = tomllib.loads(data.decode())
    # Host and target builds can supply different *unused* patches. These do
    # not participate in resolution, unlike package versions/sources/checksums.
    if 'patch' in value:
        value['patch'].pop('unused', None)
        if not value['patch']:
            del value['patch']
    return value


def run(lock, command):
    """Keep every resulting lock change, including diagnostics/order-only changes."""
    before = lock.read_bytes() if lock.exists() else None
    result = subprocess.run(command)
    if lock.is_file() and lock.read_bytes() != before:
        print(f'Cargo updated {lock}; retain and commit the resulting lockfile.', file=sys.stderr)
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
