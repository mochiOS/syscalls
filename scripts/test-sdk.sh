#!/usr/bin/env bash
set -euo pipefail
USER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# == 1 ]] || { echo "Usage: $0 SDK_DIRECTORY" >&2; exit 2; }
SDK="$(cd "$1" && pwd)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
cp -a "$SDK" "$test_root/relocated sdk"
cp "$USER_ROOT/libc-port/tests/hello.c" "$test_root/hello.c"
cd "$test_root"
compiler="$test_root/relocated sdk/bin/mochios-cc"
"$compiler" -O2 -c hello.c -o hello.o
"$compiler" hello.o -o hello.elf
[[ -z "$(nm -u hello.elf)" ]] || { echo "unresolved symbols" >&2; exit 1; }
readelf -h hello.elf | grep -q 'Advanced Micro Devices X86-64'
readelf -h hello.elf | grep -q 'EXEC (Executable file)'
[[ -z "$(find 'relocated sdk' -type l)" ]] || { echo "SDK must not depend on external symlinks" >&2; exit 1; }
echo "PASS: relocated SDK compiles and links a standalone x86-64 executable"
