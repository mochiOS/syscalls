#!/usr/bin/env python3
"""Build the isolated host fixture and verify C ownership, limits and fork safety.

Requires the user workspace's pinned nightly toolchain and a Linux C compiler.
This never adds test trust to an SDK or a mochiOS binary.
"""
import argparse
from pathlib import Path
import subprocess
import shutil

root = Path(__file__).resolve().parents[3]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
output = args.output.resolve()
output.mkdir(parents=True, exist_ok=True)
toolchain = 'nightly-2026-05-14'
subprocess.run(['cargo', '+' + toolchain, 'build', '-p', 'mochios-tls-stream-ffi',
                '--release', '--features', 'test-fixtures',
                '-Zbuild-std=core,alloc,compiler_builtins',
                '--target', 'x86_64-unknown-linux-gnu', '--target-dir', str(output/'rust')],
               cwd=root, check=True)
include = output/'include/mochios'
include.mkdir(parents=True, exist_ok=True)
shutil.copy2(root/'libc-port/include/mochios/tls.h', include/'tls.h')
archive = output/'rust/x86_64-unknown-linux-gnu/release/libmochios_tls_stream_ffi.a'
subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O2',
                '-I'+str(output/'include'), str(root/'crates/tls-stream-ffi/native/tls.c'),
                str(root/'crates/tls-stream-ffi/tests/ownership.c'), str(archive),
                '-pthread', '-ldl', '-lm', '-o', str(output/'ownership')], check=True)
subprocess.run([str(output/'ownership')], check=True)
print('C ABI ownership, admission limits, stale handles and fork invalidation: PASS')
