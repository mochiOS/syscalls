#!/usr/bin/env bash
set -euo pipefail
# Compatibility entrypoint: the C sysroot and runtime have one SDK builder.
USER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$USER_ROOT/scripts/build-newlib.sh" "$@"
