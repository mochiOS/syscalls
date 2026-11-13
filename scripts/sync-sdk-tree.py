#!/usr/bin/env python3
"""Publish a prepared SDK tree without changing unchanged compiler inputs."""
import filecmp
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile


def remove(path):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def sync(source, destination):
    """Mirror files, modes and links, preserving unchanged files and timestamps."""
    filecmp.clear_cache()
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        remove(destination)
    destination.mkdir(parents=True, exist_ok=True)
    for target in destination.iterdir():
        origin = source / target.name
        if not origin.exists() and not origin.is_symlink():
            remove(target)
    for origin in source.iterdir():
        target = destination / origin.name
        metadata = origin.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            link = os.readlink(origin)
            if target.is_symlink() and os.readlink(target) == link:
                continue
            if target.exists() or target.is_symlink():
                remove(target)
            target.symlink_to(link)
        elif stat.S_ISDIR(metadata.st_mode):
            sync(origin, target)
        elif stat.S_ISREG(metadata.st_mode):
            if target.is_symlink() or (target.exists() and not target.is_file()):
                remove(target)
            if not target.is_file() or not filecmp.cmp(origin, target, shallow=False):
                descriptor, name = tempfile.mkstemp(prefix='.sdk-', dir=destination)
                os.close(descriptor)
                try:
                    shutil.copy2(origin, name)
                    os.replace(name, target)
                finally:
                    Path(name).unlink(missing_ok=True)
            if stat.S_IMODE(target.stat().st_mode) != stat.S_IMODE(metadata.st_mode):
                target.chmod(stat.S_IMODE(metadata.st_mode))
        else:
            raise ValueError(f'Unsupported SDK entry: {origin}')
    destination.chmod(stat.S_IMODE(source.stat().st_mode))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: sync-sdk-tree.py <prepared-source> <destination>')
    source, destination = (Path(value).resolve() for value in sys.argv[1:])
    if not source.is_dir() or source == destination or source in destination.parents or destination in source.parents:
        raise SystemExit('SDK source and destination must be separate directories')
    sync(source, destination)
