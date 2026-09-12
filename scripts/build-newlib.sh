#!/usr/bin/env bash
set -euo pipefail
USER_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="$USER_ROOT/target/newlib-sdk"
NEWLIB_SOURCE=""
NEWLIB_SYSROOT=""
ABI_SOURCE=""
TOOLCHAIN=""
JOBS="${JOBS:-8}"
while (($#)); do
    case "$1" in
        --newlib-source) NEWLIB_SOURCE="$2"; shift 2 ;;
        --newlib-sysroot) NEWLIB_SYSROOT="$2"; shift 2 ;;
        --output) OUT_ROOT="$2"; shift 2 ;;
        --abi-source) ABI_SOURCE="$2"; shift 2 ;;
        --toolchain) TOOLCHAIN="$2"; shift 2 ;;
        --jobs) JOBS="$2"; shift 2 ;;
        --help)
            echo "Usage: $0 (--newlib-source DIR | --newlib-sysroot DIR) [--output DIR] [--abi-source DIR] [--toolchain NAME] [--jobs N]"
            echo "Builds a relocatable C SDK without a kernel or mochiOS workspace."
            echo "Requires Cargo with rust-src and x86_64-elf GCC. CARGO_NET_OFFLINE=true enables offline builds."
            exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo "invalid jobs" >&2; exit 2; }
if [[ -n "$NEWLIB_SOURCE" && -z "$NEWLIB_SYSROOT" ]]; then
    [[ -f "$NEWLIB_SOURCE/configure" ]] || { echo "--newlib-source must contain configure" >&2; exit 2; }
    NEWLIB_SOURCE="$(cd "$NEWLIB_SOURCE" && pwd)"
elif [[ -n "$NEWLIB_SYSROOT" && -z "$NEWLIB_SOURCE" ]]; then
    NEWLIB_SYSROOT="$(cd "$NEWLIB_SYSROOT" && pwd)"
    [[ -f "$NEWLIB_SYSROOT/lib/libc.a" && -f "$NEWLIB_SYSROOT/lib/libm.a" && -d "$NEWLIB_SYSROOT/include" ]] || {
        echo "invalid newlib sysroot" >&2; exit 2;
    }
else
    echo "select exactly one newlib source or prebuilt sysroot" >&2; exit 2
fi
mkdir -p "$OUT_ROOT"
OUT_ROOT="$(cd "$OUT_ROOT" && pwd)"
for cmd in cargo make nm readelf x86_64-elf-gcc x86_64-elf-ar x86_64-elf-ranlib; do
    command -v "$cmd" >/dev/null || { echo "missing command: $cmd" >&2; exit 1; }
done
cargo_args=()
[[ -z "$TOOLCHAIN" ]] || cargo_args+=("+$TOOLCHAIN")
patch_args=()
if [[ -n "$ABI_SOURCE" ]]; then
    ABI_SOURCE="$(cd "$ABI_SOURCE" && pwd)"
    [[ -f "$ABI_SOURCE/Cargo.toml" ]] || { echo "invalid ABI source" >&2; exit 2; }
    patch_args+=(--config "patch.\"https://github.com/mochiOS/mnu\".mnu-abi.path='$ABI_SOURCE'")
fi
# Separate objects from older builds that embedded host paths.
BUILD_DIR="$OUT_ROOT/build-newlib-remapped"
INSTALL_ROOT="$OUT_ROOT/toolchain"
SYSROOT="${NEWLIB_SYSROOT:-$INSTALL_ROOT/x86_64-elf}"
TARGET_DIR="$OUT_ROOT/cargo-target"
SDK="$OUT_ROOT/sdk"
mkdir -p "$BUILD_DIR" "$INSTALL_ROOT" "$TARGET_DIR" "$SDK/bin" "$SDK/lib" "$SDK/share" "$OUT_ROOT/hello"
# Source builds use make's dependency tracking; a supplied sysroot is immutable input.
if [[ -n "$NEWLIB_SOURCE" ]]; then
    if [[ ! -f "$BUILD_DIR/Makefile" ]]; then
        (cd "$BUILD_DIR"
         CC_FOR_TARGET=x86_64-elf-gcc AR_FOR_TARGET=x86_64-elf-ar RANLIB_FOR_TARGET=x86_64-elf-ranlib \
         "$NEWLIB_SOURCE/configure" --target=x86_64-elf --prefix="$INSTALL_ROOT" \
             --disable-binutils --disable-gas --disable-gdb --disable-gprof \
             --disable-libgloss --disable-multilib --disable-nls --disable-shared \
             --disable-sim --disable-werror --disable-newlib-supplied-syscalls \
             --enable-newlib-multithread=no --enable-newlib-retargetable-locking)
    elif ! grep -Fqx "srcdir = $NEWLIB_SOURCE" "$BUILD_DIR/Makefile"; then
        echo "newlib source changed; select a separate --output to preserve the existing build" >&2
        exit 2
    fi
    target_cflags="-O2 -g0 -ffile-prefix-map=$NEWLIB_SOURCE=/src/newlib -ffile-prefix-map=$OUT_ROOT=/build/newlib"
    make -C "$BUILD_DIR" -j"$JOBS" CFLAGS_FOR_TARGET="$target_cflags" all-target-newlib
    make -C "$BUILD_DIR" CFLAGS_FOR_TARGET="$target_cflags" install-target-newlib
else
    echo "[cache] use supplied newlib sysroot"
fi

cd "$USER_ROOT"
RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=/build --remap-path-prefix=$USER_ROOT=/src/user" \
cargo "${cargo_args[@]}" build -Z json-target-spec -Z build-std=core,compiler_builtins \
    --manifest-path "$USER_ROOT/Cargo.toml" --package mochi-user-newlib-runtime \
    --release --target "$USER_ROOT/targets/x86_64-unknown-mochios.json" \
    --target-dir "$TARGET_DIR" "${patch_args[@]}"
x86_64-elf-gcc -c "$USER_ROOT/runtime/crt0.S" -o "$OUT_ROOT/hello/crt0.o"
install -C -m 0644 "$OUT_ROOT/hello/crt0.o" "$SDK/lib/crt0.o"
install -C -m 0644 "$TARGET_DIR/x86_64-unknown-mochios/release/libmochi_user_newlib_runtime.a" "$SDK/lib/libmochi_user_newlib_runtime.a"
install -C -m 0644 "$USER_ROOT/runtime/linker.ld" "$SDK/lib/linker.ld"
install -C -m 0644 "$USER_ROOT/targets/x86_64-unknown-mochios.json" "$SDK/share/x86_64-unknown-mochios.json"
install -C -m 0755 "$USER_ROOT/scripts/mochios-cc" "$SDK/bin/mochios-cc"

SYSROOT_STAMP="$SDK/sysroot/.newlib-installed"

if [[ ! -f "$SYSROOT_STAMP" ||
      "$SYSROOT/lib/libc.a" -nt "$SYSROOT_STAMP" ||
      "$SYSROOT/lib/libm.a" -nt "$SYSROOT_STAMP" ]]; then
	rm -rf "$SDK/sysroot"
	mkdir -p "$SDK/sysroot"
	cp -a "$SYSROOT/include" "$SYSROOT/lib" "$SDK/sysroot/"
	touch "$SYSROOT_STAMP"
else
	echo "[cache] reuse newlib SDK sysroot"
fi

"$SDK/bin/mochios-cc" -O2 "$USER_ROOT/libc-port/tests/hello.c" -o "$OUT_ROOT/hello/hello.elf"
[[ -z "$(nm -u "$OUT_ROOT/hello/hello.elf")" ]] || { echo "unresolved symbols in hello.elf" >&2; exit 1; }
readelf -h "$OUT_ROOT/hello/hello.elf"
echo "[done] SDK: $SDK"
